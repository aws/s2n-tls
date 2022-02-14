// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::raw::{
    error::{Error, Fallible},
    security,
};
use alloc::sync::Arc;
use core::{convert::TryInto, ptr::NonNull};
use s2n_tls_sys::*;
use std::ffi::CString;

struct Owned(NonNull<s2n_config>);

/// Safety: s2n_config objects can be sent across threads
unsafe impl Send for Owned {}

impl Default for Owned {
    fn default() -> Self {
        Self::new()
    }
}

impl Owned {
    fn new() -> Self {
        crate::raw::init::init();
        let config = unsafe { s2n_config_new().into_result() }.unwrap();
        Self(config)
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut s2n_config {
        self.0.as_ptr()
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        let _ = unsafe { s2n_config_free(self.0.as_ptr()).into_result() };
    }
}

#[derive(Clone, Default)]
pub struct Config(Arc<Owned>);

/// Safety: s2n_config objects can be sent across threads
#[allow(unknown_lints, clippy::non_send_fields_in_send_ty)]
unsafe impl Send for Config {}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> Builder {
        Builder::default()
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut s2n_config {
        (self.0).0.as_ptr()
    }
}

#[derive(Default)]
pub struct Builder(Owned);

impl Builder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn set_alert_behavior(
        &mut self,
        value: s2n_alert_behavior::Type,
    ) -> Result<&mut Self, Error> {
        unsafe { s2n_config_set_alert_behavior(self.as_mut_ptr(), value).into_result() }?;
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
    /// and of length protocol_count. When acting as an S2N_CLIENT the protocol list is
    /// included in the Client Hello message as the ALPN extension. As an S2N_SERVER, the
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

    /// # Safety
    ///
    /// The `context` pointer must live at least as long as the config
    pub unsafe fn set_verify_host_callback(
        &mut self,
        callback: s2n_verify_host_fn,
        context: *mut core::ffi::c_void,
    ) -> Result<&mut Self, Error> {
        s2n_config_set_verify_host_callback(self.as_mut_ptr(), callback, context).into_result()?;
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

    pub fn build(self) -> Result<Config, Error> {
        Ok(Config(Arc::new(self.0)))
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
