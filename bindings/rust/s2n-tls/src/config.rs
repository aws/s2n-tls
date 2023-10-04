// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    callbacks::*,
    enums::*,
    error::{Error, Fallible},
    security,
};
use core::{convert::TryInto, ptr::NonNull};
use s2n_tls_sys::*;
use std::{
    ffi::{c_void, CString},
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, SystemTime},
};

#[derive(Debug, PartialEq)]
pub struct Config(NonNull<s2n_config>);

/// # Safety
///
/// Safety: s2n_config objects can be sent across threads
unsafe impl Send for Config {}

/// # Safety
///
/// Safety: All C methods that mutate the s2n_config are wrapped
/// in Rust methods that require a mutable reference.
unsafe impl Sync for Config {}

impl Config {
    /// Returns a Config object with pre-defined defaults.
    ///
    /// Use the [`Builder`] if custom configuration is desired.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a Builder which can be used to configure the Config
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// # Safety
    ///
    /// This config _MUST_ have been initialized with a [`Builder`].
    /// Additionally, this does NOT increment the config reference count,
    /// so consider cloning the result if the source pointer is still
    /// valid and usable afterwards.
    pub(crate) unsafe fn from_raw(config: NonNull<s2n_config>) -> Self {
        let config = Self(config);

        // Check if the context can be retrieved.
        // If it can't, this is not a valid config.
        config.context();

        config
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut s2n_config {
        self.0.as_ptr()
    }

    /// Retrieve a reference to the [`Context`] stored on the config.
    pub(crate) fn context(&self) -> &Context {
        let mut ctx = core::ptr::null_mut();
        unsafe {
            s2n_config_get_ctx(self.0.as_ptr(), &mut ctx)
                .into_result()
                .unwrap();
            &*(ctx as *const Context)
        }
    }

    /// Retrieve a mutable reference to the [`Context`] stored on the config.
    pub(crate) fn context_mut(&mut self) -> &mut Context {
        let mut ctx = core::ptr::null_mut();
        unsafe {
            s2n_config_get_ctx(self.as_mut_ptr(), &mut ctx)
                .into_result()
                .unwrap();
            &mut *(ctx as *mut Context)
        }
    }

    #[cfg(test)]
    /// Get the refcount associated with the config
    pub fn test_get_refcount(&self) -> Result<usize, Error> {
        let context = self.context();
        Ok(context.refcount.load(Ordering::SeqCst))
    }
}

impl Default for Config {
    fn default() -> Self {
        Builder::new().build().unwrap()
    }
}

impl Clone for Config {
    fn clone(&self) -> Self {
        let context = self.context();

        // Safety
        //
        // Using a relaxed ordering is alright here, as knowledge of the
        // original reference prevents other threads from erroneously deleting
        // the object.
        // https://github.com/rust-lang/rust/blob/e012a191d768adeda1ee36a99ef8b92d51920154/library/alloc/src/sync.rs#L1329
        let _count = context.refcount.fetch_add(1, Ordering::Relaxed);
        Self(self.0)
    }
}

impl Drop for Config {
    fn drop(&mut self) {
        let context = self.context_mut();
        let count = context.refcount.fetch_sub(1, Ordering::Release);
        debug_assert!(count > 0, "refcount should not drop below 1 instance");

        // only free the config if this is the last instance
        if count != 1 {
            return;
        }

        // Safety
        //
        // The use of Ordering and fence mirrors the `Arc` implementation in
        // the standard library.
        //
        // This fence is needed to prevent reordering of use of the data and
        // deletion of the data.  Because it is marked `Release`, the decreasing
        // of the reference count synchronizes with this `Acquire` fence. This
        // means that use of the data happens before decreasing the reference
        // count, which happens before this fence, which happens before the
        // deletion of the data.
        // https://github.com/rust-lang/rust/blob/e012a191d768adeda1ee36a99ef8b92d51920154/library/alloc/src/sync.rs#L1637
        std::sync::atomic::fence(Ordering::Acquire);

        unsafe {
            // This is the last instance so free the context.
            let context = Box::from_raw(context);
            drop(context);

            let _ = s2n_config_free(self.0.as_ptr()).into_result();
        }
    }
}

#[derive(Default)]
pub struct Builder {
    config: Config,
    load_system_certs: bool,
    enable_ocsp: bool,
}

impl Builder {
    pub fn new() -> Self {
        crate::init::init();
        let config = unsafe { s2n_config_new_minimal().into_result() }.unwrap();

        let context = Box::<Context>::default();
        let context = Box::into_raw(context) as *mut c_void;

        unsafe {
            s2n_config_set_ctx(config.as_ptr(), context)
                .into_result()
                .unwrap();

            // The client hello callback originally did not support async operations,
            // so defaults to blocking mode for backwards compatibility with old integrations.
            // But these bindings use a polling model, so assume non-blocking mode.
            s2n_config_set_client_hello_cb_mode(
                config.as_ptr(),
                s2n_client_hello_cb_mode::NONBLOCKING,
            )
            .into_result()
            .unwrap();
        }

        Self {
            config: Config(config),
            load_system_certs: true,
            enable_ocsp: false,
        }
    }

    pub fn set_alert_behavior(&mut self, value: AlertBehavior) -> Result<&mut Self, Error> {
        unsafe { s2n_config_set_alert_behavior(self.as_mut_ptr(), value.into()).into_result() }?;
        Ok(self)
    }

    pub fn set_security_policy(&mut self, policy: &security::Policy) -> Result<&mut Self, Error> {
        unsafe {
            s2n_config_set_cipher_preferences(self.as_mut_ptr(), policy.as_cstr().as_ptr())
                .into_result()
        }?;
        Ok(self)
    }

    /// sets the application protocol preferences on an s2n_config object.
    ///
    /// protocols is a list in order of preference, with most preferred protocol first,
    /// and of length protocol_count. When acting as a client the protocol list is
    /// included in the Client Hello message as the ALPN extension. As a server, the
    /// list is used to negotiate a mutual application protocol with the client. After
    /// the negotiation for the connection has completed, the agreed upon protocol can
    /// be retrieved with s2n_get_application_protocol
    pub fn set_application_protocol_preference<P: IntoIterator<Item = I>, I: AsRef<[u8]>>(
        &mut self,
        protocols: P,
    ) -> Result<&mut Self, Error> {
        // reset the list
        unsafe {
            s2n_config_set_protocol_preferences(self.as_mut_ptr(), core::ptr::null(), 0)
                .into_result()
        }?;

        for protocol in protocols {
            self.append_application_protocol_preference(protocol.as_ref())?;
        }

        Ok(self)
    }

    pub fn append_application_protocol_preference(
        &mut self,
        protocol: &[u8],
    ) -> Result<&mut Self, Error> {
        unsafe {
            s2n_config_append_protocol_preference(
                self.as_mut_ptr(),
                protocol.as_ptr(),
                protocol
                    .len()
                    .try_into()
                    .map_err(|_| Error::INVALID_INPUT)?,
            )
            .into_result()
        }?;
        Ok(self)
    }

    /// Turns off x509 verification
    ///
    /// # Safety
    /// This functionality will weaken the security of the connections. As such, it should only
    /// be used in development environments where obtaining a valid certificate would not be possible.
    pub unsafe fn disable_x509_verification(&mut self) -> Result<&mut Self, Error> {
        s2n_config_disable_x509_verification(self.as_mut_ptr()).into_result()?;
        Ok(self)
    }

    pub fn add_dhparams(&mut self, pem: &[u8]) -> Result<&mut Self, Error> {
        let cstring = CString::new(pem).map_err(|_| Error::INVALID_INPUT)?;
        unsafe { s2n_config_add_dhparams(self.as_mut_ptr(), cstring.as_ptr()).into_result() }?;
        Ok(self)
    }

    pub fn load_pem(&mut self, certificate: &[u8], private_key: &[u8]) -> Result<&mut Self, Error> {
        let certificate = CString::new(certificate).map_err(|_| Error::INVALID_INPUT)?;
        let private_key = CString::new(private_key).map_err(|_| Error::INVALID_INPUT)?;
        unsafe {
            s2n_config_add_cert_chain_and_key(
                self.as_mut_ptr(),
                certificate.as_ptr(),
                private_key.as_ptr(),
            )
            .into_result()
        }?;
        Ok(self)
    }

    pub fn load_public_pem(&mut self, certificate: &[u8]) -> Result<&mut Self, Error> {
        let size: u32 = certificate
            .len()
            .try_into()
            .map_err(|_| Error::INVALID_INPUT)?;
        let certificate = certificate.as_ptr() as *mut u8;
        unsafe { s2n_config_add_cert_chain(self.as_mut_ptr(), certificate, size) }.into_result()?;
        Ok(self)
    }

    pub fn trust_pem(&mut self, certificate: &[u8]) -> Result<&mut Self, Error> {
        let certificate = CString::new(certificate).map_err(|_| Error::INVALID_INPUT)?;
        unsafe {
            s2n_config_add_pem_to_trust_store(self.as_mut_ptr(), certificate.as_ptr()).into_result()
        }?;
        Ok(self)
    }

    /// Adds to the trust store from a CA file or directory containing trusted certificates.
    ///
    /// NOTE: This function is equivalent to `s2n_config_set_verification_ca_location` except it does
    /// not automatically enable the client to request OCSP stapling from the server.
    pub fn trust_location(
        &mut self,
        file: Option<&Path>,
        dir: Option<&Path>,
    ) -> Result<&mut Self, Error> {
        fn to_cstr(input: Option<&Path>) -> Result<Option<CString>, Error> {
            Ok(match input {
                Some(input) => {
                    let string = input.to_str().ok_or(Error::INVALID_INPUT)?;
                    let cstring = CString::new(string).map_err(|_| Error::INVALID_INPUT)?;
                    Some(cstring)
                }
                None => None,
            })
        }

        let file_cstr = to_cstr(file)?;
        let file_ptr = file_cstr
            .as_ref()
            .map(|f| f.as_ptr())
            .unwrap_or(core::ptr::null());

        let dir_cstr = to_cstr(dir)?;
        let dir_ptr = dir_cstr
            .as_ref()
            .map(|f| f.as_ptr())
            .unwrap_or(core::ptr::null());

        unsafe {
            s2n_config_set_verification_ca_location(self.as_mut_ptr(), file_ptr, dir_ptr)
                .into_result()
        }?;

        // If OCSP has not been explicitly requested, turn off OCSP. This is to prevent this function from
        // automatically enabling `OCSP` due to the legacy behavior of `s2n_config_set_verification_ca_location`
        if !self.enable_ocsp {
            unsafe {
                s2n_config_set_status_request_type(self.as_mut_ptr(), s2n_status_request_type::NONE)
                    .into_result()?
            };
        }

        Ok(self)
    }

    /// Sets whether or not default system certificates will be loaded into the trust store.
    ///
    /// Set to false for increased performance if system certificates are not needed during
    /// certificate validation.
    pub fn with_system_certs(&mut self, load_system_certs: bool) -> Result<&mut Self, Error> {
        self.load_system_certs = load_system_certs;
        Ok(self)
    }

    pub fn wipe_trust_store(&mut self) -> Result<&mut Self, Error> {
        unsafe { s2n_config_wipe_trust_store(self.as_mut_ptr()).into_result()? };
        Ok(self)
    }

    /// Sets whether or not a client certificate should be required to complete the TLS connection.
    ///
    /// See the [Usage Guide](https://github.com/aws/s2n-tls/blob/main/docs/USAGE-GUIDE.md#client-auth-related-calls) for more details.
    pub fn set_client_auth_type(&mut self, auth_type: ClientAuthType) -> Result<&mut Self, Error> {
        unsafe {
            s2n_config_set_client_auth_type(self.as_mut_ptr(), auth_type.into()).into_result()
        }?;
        Ok(self)
    }

    /// Clients will request OCSP stapling from the server.
    pub fn enable_ocsp(&mut self) -> Result<&mut Self, Error> {
        unsafe {
            s2n_config_set_status_request_type(self.as_mut_ptr(), s2n_status_request_type::OCSP)
                .into_result()
        }?;
        self.enable_ocsp = true;
        Ok(self)
    }

    /// Sets the OCSP data for the default certificate chain associated with the Config.
    ///
    /// Servers will send the data in response to OCSP stapling requests from clients.
    //
    // NOTE: this modifies a certificate chain, NOT the Config itself. This is currently safe
    // because the certificate chain is set with s2n_config_add_cert_chain_and_key, which
    // creates a new certificate chain only accessible by the given config. It will
    // NOT be safe when we add support for the newer s2n_config_add_cert_chain_and_key_to_store API,
    // which allows certificate chains to be shared across configs.
    // In that case, we'll need additional guard rails either in these bindings or in the underlying C.
    pub fn set_ocsp_data(&mut self, data: &[u8]) -> Result<&mut Self, Error> {
        let size: u32 = data.len().try_into().map_err(|_| Error::INVALID_INPUT)?;
        unsafe {
            s2n_config_set_extension_data(
                self.as_mut_ptr(),
                s2n_tls_extension_type::OCSP_STAPLING,
                data.as_ptr(),
                size,
            )
            .into_result()
        }?;
        self.enable_ocsp()
    }

    /// Sets the callback to use for verifying that a hostname from an X.509 certificate is
    /// trusted.
    ///
    /// The callback may be called more than once during certificate validation as each SAN on
    /// the certificate will be checked.
    ///
    /// Corresponds to the underlying C API
    /// [s2n_config_set_verify_host_callback](https://aws.github.io/s2n-tls/doxygen/s2n_8h.html).
    pub fn set_verify_host_callback<T: 'static + VerifyHostNameCallback>(
        &mut self,
        handler: T,
    ) -> Result<&mut Self, Error> {
        unsafe extern "C" fn verify_host_cb_fn(
            host_name: *const ::libc::c_char,
            host_name_len: usize,
            context: *mut ::libc::c_void,
        ) -> u8 {
            let context = &mut *(context as *mut Context);
            let handler = context.verify_host_callback.as_mut().unwrap();
            verify_host(host_name, host_name_len, handler)
        }

        self.config.context_mut().verify_host_callback = Some(Box::new(handler));
        unsafe {
            s2n_config_set_verify_host_callback(
                self.as_mut_ptr(),
                Some(verify_host_cb_fn),
                self.config.context_mut() as *mut Context as *mut c_void,
            )
            .into_result()?;
        }
        Ok(self)
    }

    /// # Safety
    /// THIS SHOULD BE USED FOR DEBUGGING PURPOSES ONLY!
    /// The `context` pointer must live at least as long as the config
    pub unsafe fn set_key_log_callback(
        &mut self,
        callback: s2n_key_log_fn,
        context: *mut core::ffi::c_void,
    ) -> Result<&mut Self, Error> {
        s2n_config_set_key_log_cb(self.as_mut_ptr(), callback, context).into_result()?;
        Ok(self)
    }

    pub fn set_max_cert_chain_depth(&mut self, depth: u16) -> Result<&mut Self, Error> {
        unsafe { s2n_config_set_max_cert_chain_depth(self.as_mut_ptr(), depth).into_result() }?;
        Ok(self)
    }

    pub fn set_send_buffer_size(&mut self, size: u32) -> Result<&mut Self, Error> {
        unsafe { s2n_config_set_send_buffer_size(self.as_mut_ptr(), size).into_result() }?;
        Ok(self)
    }

    /// Set a custom callback function which is run after parsing the client hello.
    pub fn set_client_hello_callback<T: 'static + ClientHelloCallback>(
        &mut self,
        handler: T,
    ) -> Result<&mut Self, Error> {
        unsafe extern "C" fn client_hello_cb(
            connection_ptr: *mut s2n_connection,
            _context: *mut core::ffi::c_void,
        ) -> libc::c_int {
            with_context(connection_ptr, |conn, context| {
                let callback = context.client_hello_callback.as_ref();
                let future = callback
                    .map(|c| c.on_client_hello(conn))
                    .unwrap_or(Ok(None));
                AsyncCallback::trigger_client_hello_cb(future, conn)
            })
            .into()
        }

        let handler = Box::new(handler);
        let context = self.config.context_mut();
        context.client_hello_callback = Some(handler);

        unsafe {
            s2n_config_set_client_hello_cb(
                self.as_mut_ptr(),
                Some(client_hello_cb),
                core::ptr::null_mut(),
            )
            .into_result()?;
        }

        Ok(self)
    }

    /// Sets a custom callback which provides access to session tickets when they arrive
    pub fn set_session_ticket_callback<T: 'static + SessionTicketCallback>(
        &mut self,
        handler: T,
    ) -> Result<&mut Self, Error> {
        // Define C callback function that can be set on the s2n_config struct
        unsafe extern "C" fn session_ticket_cb(
            conn_ptr: *mut s2n_connection,
            _context: *mut ::libc::c_void,
            session_ticket: *mut s2n_session_ticket,
        ) -> libc::c_int {
            let session_ticket = SessionTicket::from_ptr(&*session_ticket);
            with_context(conn_ptr, |conn, context| {
                let callback = context.session_ticket_callback.as_ref();
                callback.map(|c| c.on_session_ticket(conn, session_ticket))
            });
            CallbackResult::Success.into()
        }

        // Store callback in context
        let handler = Box::new(handler);
        let context = self.config.context_mut();
        context.session_ticket_callback = Some(handler);

        unsafe {
            s2n_config_set_session_ticket_cb(
                self.as_mut_ptr(),
                Some(session_ticket_cb),
                self.config.context_mut() as *mut Context as *mut c_void,
            )
            .into_result()
        }?;
        Ok(self)
    }

    /// Set a callback function triggered by operations requiring the private key.
    ///
    /// See https://github.com/aws/s2n-tls/blob/main/docs/USAGE-GUIDE.md#private-key-operation-related-calls
    pub fn set_private_key_callback<T: 'static + PrivateKeyCallback>(
        &mut self,
        handler: T,
    ) -> Result<&mut Self, Error> {
        unsafe extern "C" fn private_key_cb(
            conn_ptr: *mut s2n_connection,
            op_ptr: *mut s2n_async_pkey_op,
        ) -> libc::c_int {
            with_context(conn_ptr, |conn, context| {
                let state = PrivateKeyOperation::try_from_cb(conn, op_ptr);
                let callback = context.private_key_callback.as_ref();
                let future_result = state.and_then(|state| {
                    callback.map_or(Ok(None), |callback| callback.handle_operation(conn, state))
                });
                AsyncCallback::trigger(future_result, conn)
            })
            .into()
        }

        let handler = Box::new(handler);
        let context = self.config.context_mut();
        context.private_key_callback = Some(handler);

        unsafe {
            s2n_config_set_async_pkey_callback(self.as_mut_ptr(), Some(private_key_cb))
                .into_result()?;
        }
        Ok(self)
    }

    /// Set a callback function that will be used to get the system time.
    ///
    /// The wall clock time is the best-guess at the real time, measured since the epoch.
    /// Unlike monotonic time, it CAN move backwards.
    /// It is used by s2n-tls for timestamps.
    pub fn set_wall_clock<T: 'static + WallClock>(
        &mut self,
        handler: T,
    ) -> Result<&mut Self, Error> {
        unsafe extern "C" fn clock_cb(
            context: *mut ::libc::c_void,
            time_in_nanos: *mut u64,
        ) -> libc::c_int {
            let context = &mut *(context as *mut Context);
            if let Some(handler) = context.wall_clock.as_mut() {
                if let Ok(nanos) = handler.get_time_since_epoch().as_nanos().try_into() {
                    *time_in_nanos = nanos;
                    return CallbackResult::Success.into();
                }
            }
            CallbackResult::Failure.into()
        }

        let handler = Box::new(handler);
        let context = self.config.context_mut();
        context.wall_clock = Some(handler);
        unsafe {
            s2n_config_set_wall_clock(
                self.as_mut_ptr(),
                Some(clock_cb),
                self.config.context_mut() as *mut _ as *mut c_void,
            )
            .into_result()?;
        }
        Ok(self)
    }

    /// Set a callback function that will be used to get the monotonic time.
    ///
    /// The monotonic time is the time since an arbitrary, unspecified point.
    /// Unlike wall clock time, it MUST never move backwards.
    /// It is used by s2n-tls for timers.
    pub fn set_monotonic_clock<T: 'static + MonotonicClock>(
        &mut self,
        handler: T,
    ) -> Result<&mut Self, Error> {
        unsafe extern "C" fn clock_cb(
            context: *mut ::libc::c_void,
            time_in_nanos: *mut u64,
        ) -> libc::c_int {
            let context = &mut *(context as *mut Context);
            if let Some(handler) = context.monotonic_clock.as_mut() {
                if let Ok(nanos) = handler.get_time().as_nanos().try_into() {
                    *time_in_nanos = nanos;
                    return CallbackResult::Success.into();
                }
            }
            CallbackResult::Failure.into()
        }

        let handler = Box::new(handler);
        let context = self.config.context_mut();
        context.monotonic_clock = Some(handler);
        unsafe {
            s2n_config_set_monotonic_clock(
                self.as_mut_ptr(),
                Some(clock_cb),
                self.config.context_mut() as *mut _ as *mut c_void,
            )
            .into_result()?;
        }
        Ok(self)
    }

    /// Enable negotiating session tickets in a TLS connection
    pub fn enable_session_tickets(&mut self, enable: bool) -> Result<&mut Self, Error> {
        unsafe {
            s2n_config_set_session_tickets_onoff(self.as_mut_ptr(), enable.into()).into_result()
        }?;
        Ok(self)
    }

    /// Adds a key which will be used to encrypt and decrypt session tickets. The intro_time parameter is time since
    /// the Unix epoch (Midnight, January 1st, 1970). The key must be at least 16 bytes.
    pub fn add_session_ticket_key(
        &mut self,
        key_name: &[u8],
        key: &[u8],
        intro_time: SystemTime,
    ) -> Result<&mut Self, Error> {
        let key_name_len: u32 = key_name
            .len()
            .try_into()
            .map_err(|_| Error::INVALID_INPUT)?;
        let key_len: u32 = key.len().try_into().map_err(|_| Error::INVALID_INPUT)?;
        let intro_time = intro_time
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::INVALID_INPUT)?;
        // Ticket keys should be at least 128 bits in strength
        // https://www.rfc-editor.org/rfc/rfc5077#section-5.5
        if key_len < 16 {
            return Err(Error::INVALID_INPUT);
        }
        self.enable_session_tickets(true)?;
        unsafe {
            s2n_config_add_ticket_crypto_key(
                self.as_mut_ptr(),
                key_name.as_ptr(),
                key_name_len,
                // s2n-tls doesn't mutate key, it's just mut for easier use with stuffers and blobs
                key.as_ptr() as *mut u8,
                key_len,
                intro_time.as_secs(),
            )
            .into_result()
        }?;
        Ok(self)
    }

    // Sets how long a session ticket key will be able to be used for both encryption
    // and decryption of tickets
    pub fn set_ticket_key_encrypt_decrypt_lifetime(
        &mut self,
        lifetime: Duration,
    ) -> Result<&mut Self, Error> {
        unsafe {
            s2n_config_set_ticket_encrypt_decrypt_key_lifetime(
                self.as_mut_ptr(),
                lifetime.as_secs(),
            )
            .into_result()
        }?;
        Ok(self)
    }

    // Sets how long a session ticket key will be able to be used for only decryption
    pub fn set_ticket_key_decrypt_lifetime(
        &mut self,
        lifetime: Duration,
    ) -> Result<&mut Self, Error> {
        unsafe {
            s2n_config_set_ticket_decrypt_key_lifetime(self.as_mut_ptr(), lifetime.as_secs())
                .into_result()
        }?;
        Ok(self)
    }

    pub fn build(mut self) -> Result<Config, Error> {
        if self.load_system_certs {
            unsafe {
                s2n_config_load_system_certs(self.as_mut_ptr()).into_result()?;
            }
        }

        Ok(self.config)
    }

    fn as_mut_ptr(&mut self) -> *mut s2n_config {
        self.config.as_mut_ptr()
    }
}

#[cfg(feature = "quic")]
impl Builder {
    pub fn enable_quic(&mut self) -> Result<&mut Self, Error> {
        unsafe { s2n_tls_sys::s2n_config_enable_quic(self.as_mut_ptr()).into_result() }?;
        Ok(self)
    }
}

pub(crate) struct Context {
    refcount: AtomicUsize,
    pub(crate) client_hello_callback: Option<Box<dyn ClientHelloCallback>>,
    pub(crate) private_key_callback: Option<Box<dyn PrivateKeyCallback>>,
    pub(crate) verify_host_callback: Option<Box<dyn VerifyHostNameCallback>>,
    pub(crate) session_ticket_callback: Option<Box<dyn SessionTicketCallback>>,
    pub(crate) wall_clock: Option<Box<dyn WallClock>>,
    pub(crate) monotonic_clock: Option<Box<dyn MonotonicClock>>,
}

impl Default for Context {
    fn default() -> Self {
        // The AtomicUsize is used to manually track the reference count of the Config.
        // This mechanism is used to track when the Config object should be freed.
        let refcount = AtomicUsize::new(1);

        Self {
            refcount,
            client_hello_callback: None,
            private_key_callback: None,
            verify_host_callback: None,
            session_ticket_callback: None,
            wall_clock: None,
            monotonic_clock: None,
        }
    }
}
