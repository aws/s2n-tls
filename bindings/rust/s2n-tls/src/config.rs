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
    sync::atomic::{AtomicUsize, Ordering},
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
    /// valid and useable afterwards.
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
    fn context_mut(&mut self) -> &mut Context {
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
pub struct Builder(Config);

impl Builder {
    pub fn new() -> Self {
        crate::init::init();
        let config = unsafe { s2n_config_new().into_result() }.unwrap();

        let context = Box::new(Context::default());
        let context = Box::into_raw(context) as *mut c_void;

        unsafe {
            s2n_config_set_ctx(config.as_ptr(), context)
                .into_result()
                .unwrap();
        }

        Self(Config(config))
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
                protocol.len().try_into().map_err(|_| Error::InvalidInput)?,
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

    pub fn load_pem(&mut self, certificate: &[u8], private_key: &[u8]) -> Result<&mut Self, Error> {
        let certificate = CString::new(certificate).map_err(|_| Error::InvalidInput)?;
        let private_key = CString::new(private_key).map_err(|_| Error::InvalidInput)?;
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

    pub fn trust_pem(&mut self, certificate: &[u8]) -> Result<&mut Self, Error> {
        let certificate = CString::new(certificate).map_err(|_| Error::InvalidInput)?;
        unsafe {
            s2n_config_add_pem_to_trust_store(self.as_mut_ptr(), certificate.as_ptr()).into_result()
        }?;
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

    /// Set a custom callback function which is run during client certificate validation during
    /// a mutual TLS handshake.
    ///
    /// The callback may be called more than once during certificate validation as each SAN on
    /// the certificate will be checked.
    pub fn set_verify_host_callback<T: 'static + VerifyHostNameCallback>(
        &mut self,
        handler: T,
    ) -> Result<&mut Self, Error> {
        unsafe extern "C" fn verify_host_cb(
            host_name: *const ::libc::c_char,
            host_name_len: usize,
            context: *mut ::libc::c_void,
        ) -> u8 {
            let host_name = host_name as *const u8;
            let host_name = core::slice::from_raw_parts(host_name, host_name_len);
            if let Ok(host_name_str) = core::str::from_utf8(host_name) {
                let context = &mut *(context as *mut Context);
                let handler = context.verify_host_callback.as_mut().unwrap();
                return handler.verify_host_name(host_name_str) as u8;
            }
            0 // If the host name can't be parsed, fail closed.
        }

        let handler = Box::new(handler);
        let context = self.0.context_mut();
        context.verify_host_callback = Some(handler);
        unsafe {
            s2n_config_set_verify_host_callback(
                self.as_mut_ptr(),
                Some(verify_host_cb),
                self.0.context_mut() as *mut _ as *mut c_void,
            )
            .into_result()?;
        }
        Ok(self)
    }

    /// # Safety
    ///
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

    /// Set a custom callback function which is run after parsing the client hello.
    pub fn set_client_hello_callback<T: 'static + ClientHelloCallback>(
        &mut self,
        handler: T,
    ) -> Result<&mut Self, Error> {
        unsafe extern "C" fn client_hello_cb(
            connection_ptr: *mut s2n_connection,
            _context: *mut core::ffi::c_void,
        ) -> libc::c_int {
            with_connection(connection_ptr, |conn| {
                let callback = AsyncClientHelloCallback {};
                trigger_async_callback(callback, conn).into()
            })
        }

        let handler = Box::new(handler);
        let context = self.0.context_mut();
        context.client_hello_callback = Some(handler);

        unsafe {
            s2n_config_set_client_hello_cb_mode(
                self.as_mut_ptr(),
                s2n_client_hello_cb_mode::NONBLOCKING,
            )
            .into_result()?;
            s2n_config_set_client_hello_cb(
                self.as_mut_ptr(),
                Some(client_hello_cb),
                core::ptr::null_mut(),
            )
            .into_result()?;
        }

        Ok(self)
    }

    pub fn build(self) -> Result<Config, Error> {
        Ok(self.0)
    }

    fn as_mut_ptr(&mut self) -> *mut s2n_config {
        self.0.as_mut_ptr()
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
    pub(crate) verify_host_callback: Option<Box<dyn VerifyHostNameCallback>>,
}

impl Default for Context {
    fn default() -> Self {
        // The AtomicUsize is used to manually track the reference count of the Config.
        // This mechanism is used to track when the Config object should be freed.
        let refcount = AtomicUsize::new(1);

        Self {
            refcount,
            client_hello_callback: None,
            verify_host_callback: None,
        }
    }
}
