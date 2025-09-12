// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Certificate Authorities handling as part of CertificateRequests.
//!
//! This is an unstable s2n API.

use s2n_tls_sys::*;

use crate::{
    callbacks::with_context,
    config,
    connection::Connection,
    enums::CallbackResult,
    error::{Error, Fallible},
};
use std::{marker::PhantomData, ptr::NonNull};

/// A CertificateRequest message.
///
/// This is provided via [`CertificateRequestCallback::on_certificate_request`].
pub struct CertificateRequest<'a> {
    request: NonNull<s2n_certificate_request>,
    conn: &'a mut Connection,
}

/// A list of DER-encoded X.509 distinguished names sent by the server.
///
/// Note that s2n-tls does not validate the contents of the names, consider them untrusted input.
pub struct CertificateAuthorities<'a>(
    Option<NonNull<s2n_certificate_authority_list>>,
    PhantomData<&'a mut ()>,
);

#[derive(Default)]
pub(crate) struct CertRequestState {
    chain: Option<crate::cert_chain::CertificateChain<'static>>,
}

impl CertificateRequest<'_> {
    /// Get the list of certificate_authorities provided by the server for this request.
    ///
    /// This returns a reference to the internal state of the CertificateRequest: the iterator is
    /// not reset on each call to this method.
    ///
    /// Corresponds to [s2n_certificate_request_get_ca_list].
    pub fn certificate_authorities(&mut self) -> CertificateAuthorities<'_> {
        // SAFETY: Accessor function, with returned object bound to the appropraite lifetime.
        unsafe {
            let list = NonNull::new(s2n_certificate_request_get_ca_list(self.request.as_ptr()));
            CertificateAuthorities(list, PhantomData)
        }
    }

    /// Get the connection this request arrived on.
    pub fn connection(&mut self) -> &mut Connection {
        self.conn
    }

    /// Set the certificate chain to reply with to this request.
    ///
    /// Corresponds to [s2n_certificate_request_set_certificate].
    pub fn set_certificate(
        &mut self,
        cert_chain: crate::cert_chain::CertificateChain<'static>,
    ) -> Result<(), Error> {
        let ptr = cert_chain.as_ptr();
        self.conn.cert_request_state().chain = Some(cert_chain);

        // SAFETY: We've stashed the certificate chain provided into the Connection's context, so
        // it's going to outlive any access to it.
        //
        // Only the last call to set_certificate has any effect in s2n-tls, so we don't need to
        // keep a vec of the chains.
        unsafe {
            s2n_certificate_request_set_certificate(self.request.as_ptr(), ptr as *mut _)
                .into_result()?;
        }

        Ok(())
    }
}

impl<'a> CertificateAuthorities<'a> {
    /// Reset the iterator to the start.
    ///
    /// Corresponds to [s2n_certificate_authority_list_reread].
    pub fn reset(&mut self) -> Result<(), Error> {
        if let Some(this) = self.0.as_ref().map(|v| v.as_ptr()) {
            // SAFETY: Calling with non-null, valid pointer to a list.
            unsafe {
                s2n_certificate_authority_list_reread(this).into_result()?;
            }
        }

        Ok(())
    }
}

pub struct CertificateAuthority<'a>(&'a [u8]);

impl<'a> CertificateAuthority<'a> {
    /// Note that s2n-tls does not validate the contents of the names, consider them untrusted input.
    pub fn der(&self) -> &[u8] {
        self.0
    }
}

impl<'a> Iterator for CertificateAuthorities<'a> {
    type Item = Result<CertificateAuthority<'a>, Error>;

    /// Corresponds to:
    /// - [s2n_certificate_authority_list_has_next]
    /// - [s2n_certificate_authority_list_next]
    fn next(&mut self) -> Option<Self::Item> {
        let mut ptr = std::ptr::null_mut::<u8>();
        let mut length: u16 = 0;

        if let Some(this) = self.0.as_ref().map(|v| v.as_ptr()) {
            // SAFETY: Calling with non-null, valid pointer to a list.
            unsafe {
                if !s2n_certificate_authority_list_has_next(this) {
                    return None;
                }
            }

            // SAFETY: Calling with non-null, valid pointer to a list.
            //
            // The `ptr` and `length` are returned to users with the appropriate lifetime.
            unsafe {
                if let Err(e) =
                    s2n_certificate_authority_list_next(this, &mut ptr, &mut length).into_result()
                {
                    return Some(Err(e));
                }
            }
        }

        if ptr.is_null() {
            // Should be unreachable, but avoiding relying on that being true.
            return Some(Err(crate::error::Error::INVALID_INPUT));
        }

        // Avoid questions about whether s2n's zero-length return had a valid pointer from Rust's
        // perspective (i.e., well-aligned).
        if length == 0 {
            return Some(Ok(CertificateAuthority(&[])));
        }

        // SAFETY: The slice provided by s2n lives for the certificate request ('a),
        // and is guaranteed to be initialized by s2n. It's also immutable.
        Some(Ok(CertificateAuthority(unsafe {
            std::slice::from_raw_parts(ptr, usize::from(length))
        })))
    }
}

/// Callback for the CertificateRequest message.
pub trait CertificateRequestCallback: 'static + Send + Sync {
    /// A callback that triggers when the client receives a CertificateRequest message
    /// from the server, providing an opportunity to override the default certificate on the
    /// Config.
    fn on_certificate_request(&self, request: &mut CertificateRequest) -> Result<(), Error>;
}

impl config::Builder {
    /// Sets a method to be called when the client receives CertificateRequest message.
    ///
    /// Corresponds to [s2n_config_set_cert_request_callback].
    pub fn set_certificate_request_callback<T: 'static + CertificateRequestCallback>(
        &mut self,
        handler: T,
    ) -> Result<&mut Self, Error> {
        unsafe extern "C" fn cert_request_callback(
            conn_ptr: *mut s2n_connection,
            _context: *mut libc::c_void,
            request: *mut s2n_certificate_request,
        ) -> libc::c_int {
            let request = match NonNull::new(request) {
                Some(r) => r,
                None => return CallbackResult::Failure.into(),
            };

            with_context(conn_ptr, |conn, context| {
                let callback = context.cert_authorities.as_ref();
                if let Some(callback) = callback {
                    let mut req = CertificateRequest { request, conn };
                    match callback.on_certificate_request(&mut req) {
                        Ok(()) => return CallbackResult::Success.into(),
                        // FIXME: How do we propagate the specific err?
                        Err(_err) => return CallbackResult::Failure.into(),
                    }
                }
                CallbackResult::Success.into()
            })
        }

        let handler = Box::new(handler);
        let context = unsafe {
            // SAFETY: usage of context_mut is safe in the builder, because while
            // it is being built, the Builder is the only reference to the config.
            self.config.context_mut()
        };
        context.cert_authorities = Some(handler);
        unsafe {
            s2n_config_set_cert_request_callback(
                self.as_mut_ptr(),
                Some(cert_request_callback),
                std::ptr::null_mut(),
            )
            .into_result()?;
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cert_chain::CertificateChain,
        enums::ClientAuthType,
        security,
        testing::{config_builder, CertKeyPair, TestPair},
    };
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    struct SetCallback {
        certificate: CertificateChain<'static>,
    }

    impl super::CertificateRequestCallback for SetCallback {
        fn on_certificate_request(
            &self,
            request: &mut super::CertificateRequest,
        ) -> Result<(), super::Error> {
            request.set_certificate(self.certificate.clone())?;
            Ok(())
        }
    }

    struct ExtractCallback {
        certificate: CertificateChain<'static>,
        cas: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl super::CertificateRequestCallback for ExtractCallback {
        fn on_certificate_request(
            &self,
            request: &mut super::CertificateRequest,
        ) -> Result<(), super::Error> {
            let mut cas = self.cas.lock().unwrap();

            cas.clear();

            for ca in request.certificate_authorities() {
                cas.push(ca?.der().to_owned());
            }

            request.certificate_authorities().reset()?;

            for (idx, ca) in request.certificate_authorities().enumerate() {
                assert_eq!(cas[idx], ca?.der());
            }

            request.set_certificate(self.certificate.clone())?;
            Ok(())
        }
    }

    #[test]
    fn basic() -> Result<(), Box<dyn std::error::Error>> {
        let keypair = CertKeyPair::default();
        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_auth_type(ClientAuthType::Required)?;
            config.trust_pem(keypair.cert())?;
            config.set_certificate_request_callback(SetCallback {
                certificate: keypair.into_certificate_chain(),
            })?;
            config.build()?
        };

        let mut pair = TestPair::from_config(&config);

        // None before handshake...
        assert!(pair.server.selected_cert().is_none());
        assert!(pair.client.selected_cert().is_none());

        pair.handshake()?;

        for conn in [&pair.server, &pair.client] {
            let chain = conn.selected_cert().unwrap();
            assert_eq!(chain.len(), 1);
            for cert in chain.iter() {
                let cert = cert?;
                let cert = cert.der()?;
                assert!(!cert.is_empty());
            }
        }

        // Same config is used for both and we are doing mTLS, so both should select the same
        // certificate.
        assert_eq!(
            pair.server
                .selected_cert()
                .unwrap()
                .iter()
                .next()
                .unwrap()?
                .der()?,
            pair.client
                .selected_cert()
                .unwrap()
                .iter()
                .next()
                .unwrap()?
                .der()?
        );

        Ok(())
    }

    #[test]
    fn change_cert() -> Result<(), Box<dyn std::error::Error>> {
        let keypair = CertKeyPair::from_path("rsa_4096_sha384_client_", "cert", "key", "cert");
        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_auth_type(ClientAuthType::Required)?;
            config.trust_pem(keypair.cert())?;
            config.set_certificate_request_callback(SetCallback {
                certificate: keypair.into_certificate_chain(),
            })?;
            config.build()?
        };

        let mut pair = TestPair::from_config(&config);

        // None before handshake...
        assert!(pair.server.selected_cert().is_none());
        assert!(pair.client.selected_cert().is_none());

        pair.handshake()?;

        for conn in [&pair.server, &pair.client] {
            let chain = conn.selected_cert().unwrap();
            assert_eq!(chain.len(), 1);
            for cert in chain.iter() {
                let cert = cert?;
                let cert = cert.der()?;
                assert!(!cert.is_empty());
            }
        }

        // Server selected the default cert
        assert_eq!(
            pair.server
                .selected_cert()
                .unwrap()
                .iter()
                .next()
                .unwrap()?
                .der()?,
            CertKeyPair::default()
                .into_certificate_chain()
                .iter()
                .next()
                .unwrap()?
                .der()?
        );

        // Client selected the custom cert
        assert_eq!(
            pair.client
                .selected_cert()
                .unwrap()
                .iter()
                .next()
                .unwrap()?
                .der()?,
            keypair
                .into_certificate_chain()
                .iter()
                .next()
                .unwrap()?
                .der()?
        );

        Ok(())
    }

    #[test]
    fn ca_list_empty() -> Result<(), Box<dyn std::error::Error>> {
        let keypair = CertKeyPair::default();
        let cas = Arc::new(Mutex::new(vec![]));
        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_auth_type(ClientAuthType::Required)?;
            config.set_certificate_request_callback(ExtractCallback {
                certificate: keypair.into_certificate_chain(),
                cas: cas.clone(),
            })?;
            config.build()?
        };

        let mut pair = TestPair::from_config(&config);

        // None before handshake...
        assert!(pair.server.selected_cert().is_none());
        assert!(pair.client.selected_cert().is_none());

        pair.handshake()?;

        let cas = cas.lock().unwrap();

        // No CAs are sent by default.
        assert_eq!(cas.len(), 0);

        Ok(())
    }

    #[test]
    fn ca_list() -> Result<(), Box<dyn std::error::Error>> {
        let keypair = CertKeyPair::default();
        let cas = Arc::new(Mutex::new(vec![]));
        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_auth_type(ClientAuthType::Required)?;
            config.set_certificate_authorities_from_trust_store()?;
            config.set_certificate_request_callback(ExtractCallback {
                certificate: keypair.into_certificate_chain(),
                cas: cas.clone(),
            })?;
            config.with_system_certs(false)?;
            config.build()?
        };

        let mut pair = TestPair::from_config(&config);

        // None before handshake...
        assert!(pair.server.selected_cert().is_none());
        assert!(pair.client.selected_cert().is_none());

        pair.handshake()?;

        let cas = cas.lock().unwrap();

        assert_eq!(cas.len(), 1);
        let ca = cas.iter().next().unwrap();
        let decoded = openssl::x509::X509Name::from_der(ca)?;
        let expected =
            openssl::x509::X509Name::load_client_ca_file(CertKeyPair::default().cert_path())?;
        assert_eq!(
            decoded.try_cmp(expected.get(0).unwrap())?,
            std::cmp::Ordering::Equal
        );

        Ok(())
    }

    #[derive(Clone)]
    struct Pick(Arc<Mutex<HashMap<&'static str, crate::config::Config>>>);

    impl crate::callbacks::ClientHelloCallback for Pick {
        fn on_client_hello(
            &self,
            connection: &mut crate::connection::Connection,
        ) -> crate::callbacks::ConnectionFutureResult {
            // This uses SNI, but in principle it could select from multiple options in a way
            // unknown to the client.
            let name = connection.server_name().unwrap();

            let this = self.0.lock().unwrap();
            let config = this.get(name).expect(name).clone();

            connection.set_config(config)?;

            connection.server_name_extension_used();

            Ok(None)
        }
    }

    struct DynamicSelect;

    impl super::CertificateRequestCallback for DynamicSelect {
        fn on_certificate_request(
            &self,
            request: &mut super::CertificateRequest,
        ) -> Result<(), super::Error> {
            let a = CertKeyPair::from_path("rsa_4096_sha256_client_", "cert", "key", "cert");
            let b = CertKeyPair::from_path("rsa_4096_sha384_client_", "cert", "key", "cert");

            let reply = match request.certificate_authorities().count() {
                1 => a,
                2 => b,
                _ => unreachable!(),
            };

            request.set_certificate(reply.into_certificate_chain())?;

            Ok(())
        }
    }

    #[test]
    fn dynamic_pick() -> Result<(), Box<dyn std::error::Error>> {
        let a = CertKeyPair::from_path("rsa_4096_sha256_client_", "cert", "key", "cert");
        let b = CertKeyPair::from_path("rsa_4096_sha384_client_", "cert", "key", "cert");
        let c = CertKeyPair::from_path("rsa_4096_sha512_client_", "cert", "key", "cert");

        let mut map = HashMap::new();
        map.insert("a.example.com", {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_auth_type(ClientAuthType::Required)?;

            config.wipe_trust_store()?;
            config.trust_pem(a.cert())?;
            config.set_certificate_authorities_from_trust_store()?;

            config.build()?
        });
        map.insert("b.example.com", {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_auth_type(ClientAuthType::Required)?;

            config.wipe_trust_store()?;
            // indicate we're the 2nd one by trusting two certificates.
            // this is a hack but we don't have a nice way to create distinct subjects (what
            // s2n sends) so this is best we can easily do.
            config.trust_pem(b.cert())?;
            config.trust_pem(c.cert())?;
            config.set_certificate_authorities_from_trust_store()?;

            config.build()?
        });
        let pick = Pick(Arc::new(Mutex::new(map)));
        let server_config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_auth_type(ClientAuthType::Required)?;
            config.set_client_hello_callback(pick.clone())?;
            config.build()?
        };

        let client_config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_auth_type(ClientAuthType::Required)?;
            config.set_certificate_request_callback(DynamicSelect)?;
            config.build()?
        };

        let mut pair = TestPair::from_configs(&client_config, &server_config);

        pair.client.set_server_name("a.example.com")?;
        pair.server
            .set_waker(Some(futures_test::task::noop_waker_ref()))?;
        pair.handshake()?;

        // Client selected the custom cert (a)
        assert_eq!(
            pair.client
                .selected_cert()
                .unwrap()
                .iter()
                .next()
                .unwrap()?
                .der()?,
            a.into_certificate_chain().iter().next().unwrap()?.der()?
        );

        let mut pair = TestPair::from_configs(&client_config, &server_config);

        pair.client.set_server_name("b.example.com")?;
        pair.server
            .set_waker(Some(futures_test::task::noop_waker_ref()))?;
        pair.handshake()?;

        // Client selected the custom cert (b)
        assert_eq!(
            pair.client
                .selected_cert()
                .unwrap()
                .iter()
                .next()
                .unwrap()?
                .der()?,
            b.into_certificate_chain().iter().next().unwrap()?.der()?
        );

        // Note that the same Client config is used in both of the above connections, so this is
        // proof that we can select different client certificates depending on server-provided CAs
        // in the CertificateRequest callback.

        Ok(())
    }
}
