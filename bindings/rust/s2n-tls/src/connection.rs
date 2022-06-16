// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::missing_safety_doc)] // TODO add safety docs

use crate::{
    callbacks::*,
    config::Config,
    enums::*,
    error::{Error, Fallible, Pollable},
    security,
};
use core::{
    convert::TryInto,
    fmt,
    mem::ManuallyDrop,
    ptr::NonNull,
    task::{Poll, Waker},
};
use libc::c_void;
use s2n_tls_sys::*;
use std::{ffi::CStr, mem, time::Duration};

mod builder;
pub use builder::*;

macro_rules! static_const_str {
    ($c_chars:expr) => {
        unsafe { CStr::from_ptr($c_chars) }
            .to_str()
            .map_err(|_| Error::InvalidInput)
    };
}

pub struct Connection {
    connection: NonNull<s2n_connection>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut debug = f.debug_struct("Connection");
        if let Ok(handshake) = self.handshake_type() {
            debug.field("handshake_type", &handshake);
        }
        if let Ok(cipher) = self.cipher_suite() {
            debug.field("cipher_suite", &cipher);
        }
        if let Ok(version) = self.actual_protocol_version() {
            debug.field("actual_protocol_version", &version);
        }
        debug.finish_non_exhaustive()
    }
}

/// # Safety
///
/// s2n_connection objects can be sent across threads
unsafe impl Send for Connection {}

/// # Safety
///
/// All C methods that mutate the s2n_connection are wrapped
/// in Rust methods that require a mutable reference.
unsafe impl Sync for Connection {}

impl Connection {
    pub fn new(mode: Mode) -> Self {
        crate::init::init();

        let connection = unsafe { s2n_connection_new(mode.into()).into_result() }.unwrap();

        unsafe {
            debug_assert! {
                s2n_connection_get_config(connection.as_ptr(), &mut core::ptr::null_mut())
                    .into_result()
                    .is_err()
            }
        }

        let mut connection = Self { connection };
        connection.init_context();
        connection
    }

    fn init_context(&mut self) {
        let context = Box::new(Context::default());
        let context = Box::into_raw(context) as *mut c_void;
        // allocate a new context object
        unsafe {
            // There should never be an existing context
            debug_assert!(s2n_connection_get_ctx(self.connection.as_ptr())
                .into_result()
                .is_err());

            s2n_connection_set_ctx(self.connection.as_ptr(), context)
                .into_result()
                .unwrap();
        }
    }

    pub fn new_client() -> Self {
        Self::new(Mode::Client)
    }

    pub fn new_server() -> Self {
        Self::new(Mode::Server)
    }

    /// # Safety
    ///
    /// Caller must ensure s2n_connection is a valid reference to a [`s2n_connection`] object
    pub(crate) unsafe fn from_raw(connection: NonNull<s2n_connection>) -> Self {
        Self { connection }
    }

    /// can be used to configure s2n to either use built-in blinding (set blinding
    /// to Blinding::BuiltIn) or self-service blinding (set blinding to
    /// Blinding::SelfService).
    pub fn set_blinding(&mut self, blinding: Blinding) -> Result<&mut Self, Error> {
        unsafe {
            s2n_connection_set_blinding(self.connection.as_ptr(), blinding.into()).into_result()
        }?;
        Ok(self)
    }

    /// Reports the remaining nanoseconds before the connection may be safely closed.
    ///
    /// If [`shutdown`] is called before this method reports "0", then an error will occur.
    pub fn remaining_blinding_delay(&self) -> Result<Duration, Error> {
        let nanos = unsafe { s2n_connection_get_delay(self.connection.as_ptr()).into_result() }?;
        Ok(Duration::from_nanos(nanos))
    }

    /// Sets whether or not a Client Certificate should be required to complete the TLS Connection.
    ///
    /// If this is set to ClientAuthType::Optional the server will request a client certificate
    /// but allow the client to not provide one. Rejecting a client certificate when using
    /// ClientAuthType::Optional will terminate the handshake.
    pub fn set_client_auth_type(
        &mut self,
        client_auth_type: ClientAuthType,
    ) -> Result<&mut Self, Error> {
        unsafe {
            s2n_connection_set_client_auth_type(self.connection.as_ptr(), client_auth_type.into())
                .into_result()
        }?;
        Ok(self)
    }

    /// Attempts to drop the config on the connection.
    ///
    /// # Safety
    ///
    /// The caller must ensure the config associated with the connection was created
    /// with a [`config::Builder`].
    unsafe fn drop_config(&mut self) -> Result<(), Error> {
        let mut prev_config = core::ptr::null_mut();

        // A valid non-null pointer is returned only if the application previously called
        // [`Self::set_config()`].
        if s2n_connection_get_config(self.connection.as_ptr(), &mut prev_config)
            .into_result()
            .is_ok()
        {
            let prev_config = NonNull::new(prev_config).expect(
                "config should exist since the call to s2n_connection_get_config was successful",
            );
            drop(Config::from_raw(prev_config));
        }

        Ok(())
    }

    /// Associates a configuration object with a connection.
    pub fn set_config(&mut self, mut config: Config) -> Result<&mut Self, Error> {
        unsafe {
            // attempt to drop the currently set config
            self.drop_config()?;

            s2n_connection_set_config(self.connection.as_ptr(), config.as_mut_ptr())
                .into_result()?;

            debug_assert! {
                s2n_connection_get_config(self.connection.as_ptr(), &mut core::ptr::null_mut()).into_result().is_ok(),
                "s2n_connection_set_config was successful"
            };

            // Setting the config on the connection creates one additional reference to the config
            // so do not drop so prevent Rust from calling `drop()` at the end of this function.
            mem::forget(config);
        }

        Ok(self)
    }

    pub(crate) fn config(&self) -> Option<Config> {
        let mut raw = core::ptr::null_mut();
        let config = unsafe {
            s2n_connection_get_config(self.connection.as_ptr(), &mut raw)
                .into_result()
                .ok()?;
            let raw = NonNull::new(raw)?;
            Config::from_raw(raw)
        };
        // Because the config pointer is still set on the connection, this is a copy,
        // not the original config. This is fine -- Configs are immutable.
        let _ = ManuallyDrop::new(config.clone());
        Some(config)
    }

    pub fn set_security_policy(&mut self, policy: &security::Policy) -> Result<&mut Self, Error> {
        unsafe {
            s2n_connection_set_cipher_preferences(
                self.connection.as_ptr(),
                policy.as_cstr().as_ptr(),
            )
            .into_result()
        }?;
        Ok(self)
    }

    /// provides a smooth transition from s2n_connection_prefer_low_latency to s2n_connection_prefer_throughput.
    ///
    /// s2n_send uses small TLS records that fit into a single TCP segment for the resize_threshold
    /// bytes (cap to 8M) of data and reset record size back to a single segment after timeout_threshold
    /// seconds of inactivity.
    pub fn set_dynamic_record_threshold(
        &mut self,
        resize_threshold: u32,
        timeout_threshold: u16,
    ) -> Result<&mut Self, Error> {
        unsafe {
            s2n_connection_set_dynamic_record_threshold(
                self.connection.as_ptr(),
                resize_threshold,
                timeout_threshold,
            )
            .into_result()
        }?;
        Ok(self)
    }

    /// sets the application protocol preferences on an s2n_connection object.
    ///
    /// protocols is a list in order of preference, with most preferred protocol first, and of
    /// length protocol_count. When acting as a client the protocol list is included in the
    /// Client Hello message as the ALPN extension. As a server, the list is used to negotiate
    /// a mutual application protocol with the client. After the negotiation for the connection has
    /// completed, the agreed upon protocol can be retrieved with s2n_get_application_protocol
    pub fn set_application_protocol_preference<P: IntoIterator<Item = I>, I: AsRef<[u8]>>(
        &mut self,
        protocols: P,
    ) -> Result<&mut Self, Error> {
        // reset the list
        unsafe {
            s2n_connection_set_protocol_preferences(self.connection.as_ptr(), core::ptr::null(), 0)
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
            s2n_connection_append_protocol_preference(
                self.connection.as_ptr(),
                protocol.as_ptr(),
                protocol.len().try_into().map_err(|_| Error::InvalidInput)?,
            )
            .into_result()
        }?;
        Ok(self)
    }

    /// may be used to receive data with callbacks defined by the user.
    pub fn set_receive_callback(&mut self, callback: s2n_recv_fn) -> Result<&mut Self, Error> {
        unsafe { s2n_connection_set_recv_cb(self.connection.as_ptr(), callback).into_result() }?;
        Ok(self)
    }

    /// # Safety
    ///
    /// The `context` pointer must live at least as long as the connection
    pub unsafe fn set_receive_context(&mut self, context: *mut c_void) -> Result<&mut Self, Error> {
        s2n_connection_set_recv_ctx(self.connection.as_ptr(), context).into_result()?;
        Ok(self)
    }

    /// may be used to receive data with callbacks defined by the user.
    pub fn set_send_callback(&mut self, callback: s2n_send_fn) -> Result<&mut Self, Error> {
        unsafe { s2n_connection_set_send_cb(self.connection.as_ptr(), callback).into_result() }?;
        Ok(self)
    }

    /// # Safety
    ///
    /// The `context` pointer must live at least as long as the connection
    pub unsafe fn set_send_context(&mut self, context: *mut c_void) -> Result<&mut Self, Error> {
        s2n_connection_set_send_ctx(self.connection.as_ptr(), context).into_result()?;
        Ok(self)
    }

    /// Connections prefering low latency will be encrypted using small record sizes that
    /// can be decrypted sooner by the recipient.
    pub fn prefer_low_latency(&mut self) -> Result<&mut Self, Error> {
        unsafe { s2n_connection_prefer_low_latency(self.connection.as_ptr()).into_result() }?;
        Ok(self)
    }

    /// Connections prefering throughput will use large record sizes that minimize overhead.
    pub fn prefer_throughput(&mut self) -> Result<&mut Self, Error> {
        unsafe { s2n_connection_prefer_throughput(self.connection.as_ptr()).into_result() }?;
        Ok(self)
    }

    /// wipes and free the in and out buffers associated with a connection.
    ///
    /// This function may be called when a connection is in keep-alive or idle state to
    /// reduce memory overhead of long lived connections.
    pub fn release_buffers(&mut self) -> Result<&mut Self, Error> {
        unsafe { s2n_connection_release_buffers(self.connection.as_ptr()).into_result() }?;
        Ok(self)
    }

    pub fn use_corked_io(&mut self) -> Result<&mut Self, Error> {
        unsafe { s2n_connection_use_corked_io(self.connection.as_ptr()).into_result() }?;
        Ok(self)
    }

    /// wipes an existing connection and allows it to be reused.
    ///
    /// This method erases all data associated with a connection including pending reads.
    /// This function should be called after all I/O is completed and s2n_shutdown has been
    /// called. Reusing the same connection handle(s) is more performant than repeatedly
    /// calling s2n_connection_new and s2n_connection_free
    pub fn wipe(&mut self) -> Result<&mut Self, Error> {
        unsafe {
            // Wiping the connection will wipe the pointer to the context,
            // so retrieve and drop that memory first.
            let ctx = self.context_mut();
            drop(Box::from_raw(ctx));

            s2n_connection_wipe(self.connection.as_ptr()).into_result()
        }?;

        self.init_context();
        Ok(self)
    }

    /// Sets the currently executing async callback.
    ///
    /// Multiple callbacks can be configured for a connection and config, but
    /// [`negotiate`] can only execute and block on one callback at a time.
    /// The handshake is sequential, not concurrent, and stops execution when
    /// it encounters an async callback. It does not continue execution (and
    /// therefore can't call any other callbacks) until the blocking async callback
    /// reports completion and is no longer the "pending" callback.
    pub(crate) fn set_pending_callback(&mut self, callback: Option<Box<dyn AsyncCallback>>) {
        debug_assert!(self.context_mut().pending_callback.is_none());
        if let Some(callback) = callback {
            let _ = self.context_mut().pending_callback.insert(callback);
        }
    }

    /// Performs the TLS handshake to completion
    pub fn negotiate(&mut self) -> Poll<Result<&mut Self, Error>> {
        let mut blocked = s2n_blocked_status::NOT_BLOCKED;

        // If we blocked on a callback, poll the callback again.
        if let Some(mut callback) = self.context_mut().pending_callback.take() {
            match callback.poll(self) {
                Poll::Ready(r) => r?,
                Poll::Pending => {
                    self.set_pending_callback(Some(callback));
                    return Poll::Pending;
                }
            }
        }

        unsafe {
            s2n_negotiate(self.connection.as_ptr(), &mut blocked)
                .into_poll()
                .map_ok(|_| self)
        }
    }

    /// Encrypts and sends data on a connection where
    /// [negotiate](`Self::negotiate`) has succeeded.
    ///
    /// Returns the number of bytes written, and may indicate a partial write.
    pub fn send(&mut self, buf: &[u8]) -> Poll<Result<usize, Error>> {
        let mut blocked = s2n_blocked_status::NOT_BLOCKED;
        let buf_len: isize = buf.len().try_into().map_err(|_| Error::InvalidInput)?;
        let buf_ptr = buf.as_ptr() as *const ::libc::c_void;
        unsafe { s2n_send(self.connection.as_ptr(), buf_ptr, buf_len, &mut blocked).into_poll() }
    }

    /// Reads and decrypts data from a connection where
    /// [negotiate](`Self::negotiate`) has succeeded.
    ///
    /// Returns the number of bytes read, and may indicate a partial read.
    /// 0 bytes returned indicates EOF due to connection closure.
    pub fn recv(&mut self, buf: &mut [u8]) -> Poll<Result<usize, Error>> {
        let mut blocked = s2n_blocked_status::NOT_BLOCKED;
        let buf_len: isize = buf.len().try_into().map_err(|_| Error::InvalidInput)?;
        let buf_ptr = buf.as_ptr() as *mut ::libc::c_void;
        unsafe { s2n_recv(self.connection.as_ptr(), buf_ptr, buf_len, &mut blocked).into_poll() }
    }

    /// Attempts to flush any data previously buffered by a call to [send](`Self::negotiate`).
    pub fn flush(&mut self) -> Poll<Result<&mut Self, Error>> {
        self.send(&[0; 0]).map_ok(|_| self)
    }

    /// Attempts a graceful shutdown of the TLS connection.
    ///
    /// The shutdown is not complete until the necessary shutdown messages
    /// have been successfully sent and received. If the peer does not respond
    /// correctly, the graceful shutdown may fail.
    pub fn shutdown(&mut self) -> Poll<Result<&mut Self, Error>> {
        let mut blocked = s2n_blocked_status::NOT_BLOCKED;
        unsafe {
            s2n_shutdown(self.connection.as_ptr(), &mut blocked)
                .into_poll()
                .map_ok(|_| self)
        }
    }

    /// Returns the TLS alert code, if any
    pub fn alert(&self) -> Option<u8> {
        let alert =
            unsafe { s2n_connection_get_alert(self.connection.as_ptr()).into_result() }.ok()?;
        Some(alert as u8)
    }

    /// Sets the server name value for the connection
    pub fn set_server_name(&mut self, server_name: &str) -> Result<&mut Self, Error> {
        let server_name = std::ffi::CString::new(server_name).map_err(|_| Error::InvalidInput)?;
        unsafe {
            s2n_set_server_name(self.connection.as_ptr(), server_name.as_ptr()).into_result()
        }?;
        Ok(self)
    }

    /// Get the server name associated with the connection client hello.
    pub fn server_name(&self) -> Option<&str> {
        unsafe {
            let server_name = s2n_get_server_name(self.connection.as_ptr());
            match server_name.into_result() {
                Ok(server_name) => CStr::from_ptr(server_name).to_str().ok(),
                Err(_) => None,
            }
        }
    }

    /// Sets a Waker on the connection context or clears it if `None` is passed.
    pub fn set_waker(&mut self, waker: Option<&Waker>) -> Result<&mut Self, Error> {
        let ctx = self.context_mut();

        if let Some(waker) = waker {
            if let Some(prev_waker) = ctx.waker.as_mut() {
                // only replace the Waker if they dont reference the same task
                if !prev_waker.will_wake(waker) {
                    *prev_waker = waker.clone();
                }
            } else {
                ctx.waker = Some(waker.clone());
            }
        } else {
            ctx.waker = None;
        }
        Ok(self)
    }

    /// Returns the Waker set on the connection context.
    pub fn waker(&self) -> Option<&Waker> {
        let ctx = self.context();
        ctx.waker.as_ref()
    }

    /// Retrieve a mutable reference to the [`Context`] stored on the connection.
    fn context_mut(&mut self) -> &mut Context {
        unsafe {
            let ctx = s2n_connection_get_ctx(self.connection.as_ptr())
                .into_result()
                .unwrap();
            &mut *(ctx.as_ptr() as *mut Context)
        }
    }

    /// Retrieve a reference to the [`Context`] stored on the connection.
    fn context(&self) -> &Context {
        unsafe {
            let ctx = s2n_connection_get_ctx(self.connection.as_ptr())
                .into_result()
                .unwrap();
            &*(ctx.as_ptr() as *mut Context)
        }
    }

    /// Mark that the server_name extension was used to configure the connection.
    pub fn server_name_extension_used(&mut self) {
        // TODO: requiring the application to call this method is a pretty sharp edge.
        // Figure out if its possible to automatically call this from the Rust bindings.
        unsafe {
            s2n_connection_server_name_extension_used(self.connection.as_ptr())
                .into_result()
                .unwrap();
        }
    }

    pub(crate) fn mark_client_hello_cb_done(&mut self) -> Result<(), Error> {
        unsafe {
            s2n_client_hello_cb_done(self.connection.as_ptr()).into_result()?;
        }
        Ok(())
    }

    pub fn actual_protocol_version(&self) -> Result<Version, Error> {
        let version = unsafe {
            s2n_connection_get_actual_protocol_version(self.connection.as_ptr()).into_result()?
        };
        version.try_into()
    }

    pub fn handshake_type(&self) -> Result<&str, Error> {
        let handshake = unsafe {
            s2n_connection_get_handshake_type_name(self.connection.as_ptr()).into_result()?
        };
        // The strings returned by s2n_connection_get_handshake_type_name
        // are static and immutable after they are first calculated
        static_const_str!(handshake)
    }

    pub fn cipher_suite(&self) -> Result<&str, Error> {
        let cipher = unsafe { s2n_connection_get_cipher(self.connection.as_ptr()).into_result()? };
        // The strings returned by s2n_connection_get_cipher
        // are static and immutable since they are const fields on static const structs
        static_const_str!(cipher)
    }
}

#[derive(Default)]
struct Context {
    waker: Option<Waker>,
    pending_callback: Option<Box<dyn AsyncCallback>>,
}

#[cfg(feature = "quic")]
impl Connection {
    pub fn enable_quic(&mut self) -> Result<&mut Self, Error> {
        unsafe { s2n_connection_enable_quic(self.connection.as_ptr()).into_result() }?;
        Ok(self)
    }

    pub fn set_quic_transport_parameters(&mut self, buffer: &[u8]) -> Result<&mut Self, Error> {
        unsafe {
            s2n_connection_set_quic_transport_parameters(
                self.connection.as_ptr(),
                buffer.as_ptr(),
                buffer.len().try_into().map_err(|_| Error::InvalidInput)?,
            )
            .into_result()
        }?;
        Ok(self)
    }

    pub fn quic_transport_parameters(&mut self) -> Result<&[u8], Error> {
        let mut ptr = core::ptr::null();
        let mut len = 0;
        unsafe {
            s2n_connection_get_quic_transport_parameters(
                self.connection.as_ptr(),
                &mut ptr,
                &mut len,
            )
            .into_result()
        }?;
        let buffer = unsafe { core::slice::from_raw_parts(ptr, len as _) };
        Ok(buffer)
    }

    /// # Safety
    ///
    /// The `context` pointer must live at least as long as the connection
    pub unsafe fn set_secret_callback(
        &mut self,
        callback: s2n_secret_cb,
        context: *mut c_void,
    ) -> Result<&mut Self, Error> {
        s2n_connection_set_secret_callback(self.connection.as_ptr(), callback, context)
            .into_result()?;
        Ok(self)
    }
}

impl AsRef<Connection> for Connection {
    fn as_ref(&self) -> &Connection {
        self
    }
}

impl AsMut<Connection> for Connection {
    fn as_mut(&mut self) -> &mut Connection {
        self
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // ignore failures since there's not much we can do about it
        unsafe {
            // clean up context
            let prev_ctx = self.context_mut();
            drop(Box::from_raw(prev_ctx));
            let _ = s2n_connection_set_ctx(self.connection.as_ptr(), core::ptr::null_mut())
                .into_result();

            // cleanup config
            let _ = self.drop_config();

            // cleanup connection
            let _ = s2n_connection_free(self.connection.as_ptr()).into_result();
        }
    }
}
