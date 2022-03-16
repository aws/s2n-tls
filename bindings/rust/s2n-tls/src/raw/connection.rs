// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::missing_safety_doc)] // TODO add safety docs

use crate::raw::{
    config::Config,
    error::{Error, Fallible},
    security,
};
use core::{
    convert::TryInto,
    fmt,
    ptr::NonNull,
    task::{Poll, Waker},
};
use libc::c_void;
use s2n_tls_sys::*;
use std::{ffi::CStr, mem};

pub use s2n_tls_sys::s2n_mode;

pub struct Connection {
    connection: NonNull<s2n_connection>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Connection")
            // TODO add paths
            .finish()
    }
}

/// # Safety
///
/// Safety: s2n_connection objects can be sent across threads
unsafe impl Send for Connection {}

impl Connection {
    pub fn new(mode: s2n_mode::Type) -> Self {
        crate::raw::init::init();
        let connection = unsafe { s2n_connection_new(mode).into_result() }.unwrap();

        unsafe {
            debug_assert! {
                s2n_connection_get_config(connection.as_ptr(), &mut core::ptr::null_mut())
                    .into_result()
                    .is_err()
            }
        }
        let context = Box::new(Context::default());
        let context = Box::into_raw(context) as *mut c_void;
        // allocate a new context object
        unsafe {
            s2n_connection_set_ctx(connection.as_ptr(), context)
                .into_result()
                .unwrap();
        }

        Self { connection }
    }

    pub fn new_client() -> Self {
        Self::new(s2n_mode::CLIENT)
    }

    pub fn new_server() -> Self {
        Self::new(s2n_mode::SERVER)
    }

    /// # Safety
    ///
    /// Caller must ensure s2n_connection is a valid reference to a [`s2n_connection`] object
    pub(crate) unsafe fn from_raw(connection: NonNull<s2n_connection>) -> Self {
        Self { connection }
    }

    /// can be used to configure s2n to either use built-in blinding (set blinding
    /// to S2N_BUILT_IN_BLINDING) or self-service blinding (set blinding to
    /// S2N_SELF_SERVICE_BLINDING).
    pub fn set_blinding(&mut self, blinding: s2n_blinding::Type) -> Result<&mut Self, Error> {
        unsafe { s2n_connection_set_blinding(self.connection.as_ptr(), blinding).into_result() }?;
        Ok(self)
    }

    /// Sets whether or not a Client Certificate should be required to complete the TLS Connection.
    ///
    /// If this is set to S2N_CERT_AUTH_OPTIONAL the server will request a client certificate
    /// but allow the client to not provide one. Rejecting a client certificate when using
    /// S2N_CERT_AUTH_OPTIONAL will terminate the handshake.
    pub fn set_client_auth_type(
        &mut self,
        client_auth_type: s2n_cert_auth_type::Type,
    ) -> Result<&mut Self, Error> {
        unsafe {
            s2n_connection_set_client_auth_type(self.connection.as_ptr(), client_auth_type)
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
    /// length protocol_count. When acting as an S2N_CLIENT the protocol list is included in the
    /// Client Hello message as the ALPN extension. As an S2N_SERVER, the list is used to negotiate
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
        unsafe { s2n_connection_wipe(self.connection.as_ptr()).into_result() }?;
        Ok(self)
    }

    /// Performs the TLS handshake to completion
    pub fn negotiate(&mut self) -> Poll<Result<&mut Self, Error>> {
        let mut blocked = s2n_blocked_status::NOT_BLOCKED;

        match unsafe { s2n_negotiate(self.connection.as_ptr(), &mut blocked).into_result() } {
            Ok(_) => Ok(self).into(),
            Err(err) if err.kind() == s2n_error_type::BLOCKED => Poll::Pending,
            Err(err) => Err(err).into(),
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

    #[cfg(test)]
    /// Test if a config has been set on the connection.
    ///
    /// `s2n_connection_get_config` should return a NULL pointer if the `s2n_connection_set_config`
    /// has not been called by the application.
    pub fn test_config_exists(&mut self) -> Result<(), Error> {
        let mut config = core::ptr::null_mut();
        let _config = unsafe {
            s2n_connection_get_config(self.connection.as_ptr(), &mut config).into_result()?
        };
        Ok(())
    }
}

#[derive(Default)]
struct Context {
    waker: Option<Waker>,
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
