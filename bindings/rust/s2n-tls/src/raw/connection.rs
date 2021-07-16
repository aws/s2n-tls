// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::missing_safety_doc)] // TODO add safety docs

use crate::raw::{config::Config, error::Error};
use core::{convert::TryInto, fmt, task::Poll};
use libc::c_void;
use s2n_tls_sys::*;

pub use s2n_tls_sys::s2n_mode;

pub struct Connection {
    connection: *mut s2n_connection,
    // The config needs to be stored so the reference count is accurate
    #[allow(dead_code)]
    config: Option<Config>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Connection")
            // TODO add paths
            .finish()
    }
}

impl Connection {
    pub fn new(mode: s2n_mode::Type) -> Self {
        crate::raw::init::init();
        let connection = call!(s2n_connection_new(mode)).unwrap();
        Self {
            connection,
            config: None,
        }
    }

    /// can be used to configure s2n to either use built-in blinding (set blinding
    /// to S2N_BUILT_IN_BLINDING) or self-service blinding (set blinding to
    /// S2N_SELF_SERVICE_BLINDING).
    pub fn set_blinding(&mut self, blinding: s2n_blinding::Type) -> Result<(), Error> {
        call!(s2n_connection_set_blinding(self.connection, blinding))?;
        Ok(())
    }

    /// Sets whether or not a Client Certificate should be required to complete the TLS Connection.
    ///
    /// If this is set to S2N_CERT_AUTH_OPTIONAL the server will request a client certificate
    /// but allow the client to not provide one. Rejecting a client certificate when using
    /// S2N_CERT_AUTH_OPTIONAL will terminate the handshake.
    pub fn set_client_auth_type(
        &mut self,
        client_auth_type: s2n_cert_auth_type::Type,
    ) -> Result<(), Error> {
        call!(s2n_connection_set_client_auth_type(
            self.connection,
            client_auth_type
        ))?;
        Ok(())
    }

    /// Associates a configuration object with a connection.
    pub fn set_config(&mut self, mut config: Config) -> Result<(), Error> {
        call!(s2n_connection_set_config(
            self.connection,
            config.as_mut_ptr(),
        ))?;
        self.config = Some(config);
        Ok(())
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
    ) -> Result<(), Error> {
        call!(s2n_connection_set_dynamic_record_threshold(
            self.connection,
            resize_threshold,
            timeout_threshold
        ))?;
        Ok(())
    }

    /// sets the application protocol preferences on an s2n_connection object.
    ///
    /// protocols is a list in order of preference, with most preferred protocol first, and of
    /// length protocol_count. When acting as an S2N_CLIENT the protocol list is included in the
    /// Client Hello message as the ALPN extension. As an S2N_SERVER, the list is used to negotiate
    /// a mutual application protocol with the client. After the negotiation for the connection has
    /// completed, the agreed upon protocol can be retrieved with s2n_get_application_protocol
    pub fn set_alpn_preference<P: IntoIterator<Item = I>, I: AsRef<[u8]>>(
        &mut self,
        protocols: P,
    ) -> Result<(), Error> {
        // reset the list
        call!(s2n_connection_set_protocol_preferences(
            self.connection,
            core::ptr::null(),
            0
        ))?;

        for protocol in protocols {
            self.append_alpn_preference(protocol.as_ref())?;
        }

        Ok(())
    }

    pub fn append_alpn_preference(&mut self, protocol: &[u8]) -> Result<&mut Self, Error> {
        call!(s2n_connection_append_protocol_preference(
            self.connection,
            protocol.as_ptr(),
            protocol.len().try_into().map_err(|_| Error::InvalidInput)?,
        ))?;
        Ok(self)
    }

    /// may be used to receive data with callbacks defined by the user.
    pub fn set_receive_callback(&mut self, callback: s2n_recv_fn) -> Result<(), Error> {
        call!(s2n_connection_set_recv_cb(self.connection, callback))?;
        Ok(())
    }

    /// # Safety
    ///
    /// The `context` pointer must live at least as long as the connection
    pub unsafe fn set_receive_context(&mut self, context: *mut c_void) -> Result<(), Error> {
        call!(s2n_connection_set_recv_ctx(self.connection, context))?;
        Ok(())
    }

    /// may be used to receive data with callbacks defined by the user.
    pub fn set_send_callback(&mut self, callback: s2n_send_fn) -> Result<(), Error> {
        call!(s2n_connection_set_send_cb(self.connection, callback))?;
        Ok(())
    }

    /// # Safety
    ///
    /// The `context` pointer must live at least as long as the connection
    pub unsafe fn set_send_context(&mut self, context: *mut c_void) -> Result<(), Error> {
        call!(s2n_connection_set_send_ctx(self.connection, context))?;
        Ok(())
    }

    /// Connections prefering low latency will be encrypted using small record sizes that
    /// can be decrypted sooner by the recipient.
    pub fn prefer_low_latency(&mut self) -> Result<(), Error> {
        call!(s2n_connection_prefer_low_latency(self.connection))?;
        Ok(())
    }

    /// Connections prefering throughput will use large record sizes that minimize overhead.
    pub fn prefer_throughput(&mut self) -> Result<(), Error> {
        call!(s2n_connection_prefer_throughput(self.connection))?;
        Ok(())
    }

    /// wipes and free the in and out buffers associated with a connection.
    ///
    /// This function may be called when a connection is in keep-alive or idle state to
    /// reduce memory overhead of long lived connections.
    pub fn release_buffers(&mut self) -> Result<(), Error> {
        call!(s2n_connection_release_buffers(self.connection))?;
        Ok(())
    }

    pub fn use_corked_io(&mut self) -> Result<(), Error> {
        call!(s2n_connection_use_corked_io(self.connection))?;
        Ok(())
    }

    /// wipes an existing connection and allows it to be reused.
    ///
    /// This method erases all data associated with a connection including pending reads.
    /// This function should be called after all I/O is completed and s2n_shutdown has been
    /// called. Reusing the same connection handle(s) is more performant than repeatedly
    /// calling s2n_connection_new and s2n_connection_free
    pub fn wipe(&mut self) -> Result<(), Error> {
        call!(s2n_connection_wipe(self.connection))?;
        Ok(())
    }

    /// Performs the TLS handshake to completion
    pub fn negotiate(&mut self) -> Poll<Result<(), Error>> {
        let mut blocked = s2n_blocked_status::NOT_BLOCKED;

        match call!(s2n_negotiate(self.connection, &mut blocked)) {
            Ok(_) => Ok(()).into(),
            Err(err) if err.kind() == s2n_error_type::BLOCKED => Poll::Pending,
            Err(err) => Err(err).into(),
        }
    }

    /// Returns the TLS alert code, if any
    pub fn alert(&self) -> Option<u8> {
        let alert = call!(s2n_connection_get_alert(self.connection)).ok()?;
        Some(alert as u8)
    }

    /// Sets the SNI value for the connection
    pub fn set_sni(&mut self, sni: &[u8]) -> Result<(), Error> {
        let sni = std::ffi::CString::new(sni).map_err(|_| Error::InvalidInput)?;
        call!(s2n_set_server_name(self.connection, sni.as_ptr()))?;
        Ok(())
    }
}

#[cfg(feature = "quic")]
impl Connection {
    pub fn set_quic_transport_parameters(&mut self, buffer: &[u8]) -> Result<(), Error> {
        call!(s2n_connection_set_quic_transport_parameters(
            self.connection,
            buffer.as_ptr(),
            buffer.len().try_into().map_err(|_| Error::InvalidInput)?,
        ))?;
        Ok(())
    }

    pub fn quic_transport_parameters(&mut self) -> Result<&[u8], Error> {
        let mut ptr = core::ptr::null();
        let mut len = 0;
        call!(s2n_connection_get_quic_transport_parameters(
            self.connection,
            &mut ptr,
            &mut len,
        ))?;
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
    ) -> Result<(), Error> {
        call!(s2n_connection_set_secret_callback(
            self.connection,
            callback,
            context
        ))?;
        Ok(())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // ignore failures since there's not much we can do about it
        let _ = call!(s2n_connection_free(self.connection));
    }
}
