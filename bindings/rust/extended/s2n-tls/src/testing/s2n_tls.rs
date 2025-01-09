// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use crate::{
        callbacks::{ClientHelloCallback, ConnectionFuture, ConnectionFutureResult},
        enums::ClientAuthType,
        error::ErrorType,
        testing::{self, client_hello::*, Error, Result, *},
    };
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;
    use futures_test::task::{new_count_waker, noop_waker};
    use security::Policy;
    use std::{fs, path::Path, pin::Pin, sync::atomic::AtomicUsize};

    #[test]
    fn handshake_default() {
        let config = build_config(&security::DEFAULT).unwrap();
        assert!(TestPair::handshake_with_config(&config).is_ok());
    }

    #[test]
    fn handshake_default_tls13() {
        let config = build_config(&security::DEFAULT_TLS13).unwrap();
        assert!(TestPair::handshake_with_config(&config).is_ok());
    }

    #[test]
    fn kem_group_name_retrieval() -> Result<(), Error> {
        // PQ isn't supported
        {
            let policy = Policy::from_version("20240501")?;
            let config = build_config(&policy)?;
            let mut pair = TestPair::from_config(&config);

            // before negotiation, kem_group_name is none
            assert!(pair.client.kem_group_name().is_none());

            pair.handshake().unwrap();
            assert!(pair.client.kem_group_name().is_none());
        }

        // PQ is supported
        {
            let policy = Policy::from_version("default_pq")?;
            let config = build_config(&policy)?;
            let mut pair = TestPair::from_config(&config);

            pair.handshake().unwrap();
            assert_eq!(pair.client.kem_group_name(), Some("X25519MLKEM768"));
        }

        Ok(())
    }

    #[test]
    fn default_config_and_clone_interaction() -> Result<(), Error> {
        let config = build_config(&security::DEFAULT_TLS13)?;
        assert_eq!(config.test_get_refcount()?, 1);
        {
            // Create new connection.
            let mut server = crate::connection::Connection::new_server();
            // Can't retrieve default config.
            assert!(server.config().is_none());
            // Custom config reference count doesn't change.
            assert_eq!(config.test_get_refcount()?, 1);

            // Set custom config on connection.
            server.set_config(config.clone())?;
            // Can retrieve custom config.
            assert!(server.config().is_some());
            // Custom config now referenced once more.
            assert_eq!(config.test_get_refcount()?, 2);

            // Create new connection.
            let mut client = crate::connection::Connection::new_client();
            // Can't retrieve default config.
            assert!(client.config().is_none());
            // Custom config reference count doesn't change.
            assert_eq!(config.test_get_refcount()?, 2);

            // Set custom config on connection.
            client.set_config(config.clone())?;
            // Can retrieve custom config.
            assert!(client.config().is_some());
            // Custom config now referenced once more.
            assert_eq!(config.test_get_refcount()?, 3);

            // drop all the clones
        }
        assert_eq!(config.test_get_refcount()?, 1);
        Ok(())
    }

    #[test]
    fn set_config_multiple_times() -> Result<(), Error> {
        let config = build_config(&security::DEFAULT_TLS13)?;
        assert_eq!(config.test_get_refcount()?, 1);

        let mut server = crate::connection::Connection::new_server();
        assert_eq!(config.test_get_refcount()?, 1);

        // call set_config once
        server.set_config(config.clone())?;
        assert_eq!(config.test_get_refcount()?, 2);
        assert!(server.config().is_some());

        // calling set_config multiple times works since we drop the previous config
        server.set_config(config.clone())?;
        assert_eq!(config.test_get_refcount()?, 2);
        assert!(server.config().is_some());
        Ok(())
    }

    #[test]
    fn connnection_waker() {
        let config = build_config(&security::DEFAULT_TLS13).unwrap();
        assert_eq!(config.test_get_refcount().unwrap(), 1);

        let mut server = crate::connection::Connection::new_server();
        server.set_config(config).unwrap();

        assert!(server.waker().is_none());

        let (waker, wake_count) = new_count_waker();
        server.set_waker(Some(&waker)).unwrap();
        assert!(server.waker().is_some());

        server.set_waker(None).unwrap();
        assert!(server.waker().is_none());

        assert_eq!(wake_count, 0);
    }

    #[test]
    fn failing_client_hello_callback_sync() -> Result<(), Error> {
        let (waker, wake_count) = new_count_waker();
        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_hello_callback(FailingCHHandler)?;
            config.build()?
        };

        let mut pair = TestPair::from_config(&config);
        pair.server.set_waker(Some(&waker))?;
        let s2n_err = pair.handshake().unwrap_err();
        // the underlying error should be the custom error the application provided
        let app_err = s2n_err.application_error().unwrap();
        let io_err = app_err.downcast_ref::<std::io::Error>().unwrap();
        let _custom_err = io_err
            .get_ref()
            .unwrap()
            .downcast_ref::<CustomError>()
            .unwrap();

        assert_eq!(wake_count, 0);
        Ok(())
    }

    #[test]
    fn failing_client_hello_callback_async() -> Result<(), Error> {
        let (waker, wake_count) = new_count_waker();
        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_hello_callback(FailingAsyncCHHandler)?;
            config.build()?
        };

        let mut pair = TestPair::from_config(&config);
        pair.server.set_waker(Some(&waker))?;
        let s2n_err = pair.handshake().unwrap_err();
        // the underlying error should be the custom error the application provided
        let app_err = s2n_err.application_error().unwrap();
        let io_err = app_err.downcast_ref::<std::io::Error>().unwrap();
        let _custom_err = io_err
            .get_ref()
            .unwrap()
            .downcast_ref::<CustomError>()
            .unwrap();

        // assert that the future is async returned Poll::Pending once
        assert_eq!(wake_count, 1);
        Ok(())
    }

    #[test]
    fn client_hello_callback_async() -> Result<(), Error> {
        let (waker, wake_count) = new_count_waker();
        let require_pending_count = 10;
        let handle = MockClientHelloHandler::new(require_pending_count);
        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_hello_callback(handle.clone())?;
            // multiple calls to set_client_hello_callback should succeed
            config.set_client_hello_callback(handle.clone())?;
            config.build()?
        };

        let mut pair = TestPair::from_config(&config);
        pair.server.set_waker(Some(&waker))?;
        pair.handshake()?;

        // confirm that the callback returned Pending `require_pending_count` times
        assert_eq!(wake_count, require_pending_count);
        // confirm that the final invoked count is +1 more than `require_pending_count`
        assert_eq!(
            handle.invoked.load(Ordering::SeqCst),
            require_pending_count + 1
        );

        Ok(())
    }

    #[test]
    fn client_hello_callback_sync() -> Result<(), Error> {
        let (waker, wake_count) = new_count_waker();
        #[derive(Clone)]
        struct ClientHelloSyncCallback(Arc<AtomicUsize>);
        impl ClientHelloSyncCallback {
            fn new() -> Self {
                ClientHelloSyncCallback(Arc::new(AtomicUsize::new(0)))
            }
            fn count(&self) -> usize {
                self.0.load(Ordering::Relaxed)
            }
        }
        impl ClientHelloCallback for ClientHelloSyncCallback {
            fn on_client_hello(
                &self,
                connection: &mut crate::connection::Connection,
            ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, crate::error::Error> {
                // Test that the config can be changed
                connection
                    .set_config(build_config(&security::DEFAULT_TLS13).unwrap())
                    .unwrap();

                // Test that server_name_extension_used can be invoked
                connection.server_name_extension_used();

                self.0.fetch_add(1, Ordering::Relaxed);

                // returning `None` indicates that the client_hello callback is
                // finished and the handshake can proceed.
                Ok(None)
            }
        }
        let callback = ClientHelloSyncCallback::new();

        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_hello_callback(callback.clone())?;
            config.build()?
        };

        let mut pair = TestPair::from_config(&config);
        pair.server.set_waker(Some(&waker))?;

        assert_eq!(callback.count(), 0);

        pair.handshake()?;
        assert_eq!(callback.count(), 1);
        assert_eq!(wake_count, 0);
        Ok(())
    }

    #[test]
    fn new_security_policy() -> Result<(), Error> {
        use crate::security::Policy;

        let policy = Policy::from_version("default")?;
        config_builder(&policy)?;
        Ok(())
    }

    #[test]
    fn trust_location() -> Result<(), Error> {
        let pem_dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../certs"));
        let mut cert = pem_dir.to_path_buf();
        cert.push("cert.pem");
        let mut key = pem_dir.to_path_buf();
        key.push("key.pem");

        let mut builder = crate::config::Builder::new();
        builder.set_security_policy(&security::DEFAULT_TLS13)?;
        builder.set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;
        builder.load_pem(&fs::read(&cert)?, &fs::read(&key)?)?;
        builder.trust_location(Some(&cert), None)?;

        TestPair::handshake_with_config(&builder.build()?)?;
        Ok(())
    }

    /// `trust_location()` calls `s2n_config_set_verification_ca_location()`, which has the legacy behavior
    /// of enabling OCSP on clients. Since we do not want to replicate that behavior in the Rust bindings,
    /// this test verifies that `trust_location()` does not turn on OCSP. It also verifies that turning
    /// on OCSP explicitly still works when `trust_location()` is called.
    #[test]
    fn trust_location_does_not_change_ocsp_status() -> Result<(), Error> {
        let pem_dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../certs"));
        let mut cert = pem_dir.to_path_buf();
        cert.push("cert.pem");
        let mut key = pem_dir.to_path_buf();
        key.push("key.pem");

        const OCSP_IANA_EXTENSION_ID: u16 = 5;

        for enable_ocsp in [true, false] {
            let config = {
                let mut config = crate::config::Builder::new();

                if enable_ocsp {
                    config.enable_ocsp()?;
                }

                config.set_security_policy(&security::DEFAULT_TLS13)?;
                config.set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;
                config.set_client_hello_callback(HasExtensionClientHelloHandler {
                    // This client hello handler will check for the OCSP extension
                    extension_iana: OCSP_IANA_EXTENSION_ID,
                    extension_expected: enable_ocsp,
                })?;
                config.load_pem(&fs::read(&cert)?, &fs::read(&key)?)?;
                config.trust_location(Some(&cert), None)?;
                config.build()?
            };

            let mut pair = TestPair::from_config(&config);
            pair.server.set_waker(Some(&noop_waker()))?;
            pair.handshake()?;
        }
        Ok(())
    }

    #[test]
    fn connection_level_verify_host_callback() -> Result<(), Error> {
        let reject_config = {
            let keypair = CertKeyPair::default();
            let mut config = crate::config::Builder::new();
            // configure the config VerifyHostNameCallback to reject all certificates
            config.set_verify_host_callback(RejectAllCertificatesHandler {})?;
            config.set_security_policy(&security::DEFAULT_TLS13)?;
            config.load_pem(keypair.cert(), keypair.key())?;
            config.trust_pem(keypair.cert())?;
            config.set_client_auth_type(ClientAuthType::Required)?;
            config.build()?
        };

        // confirm that default connection establishment fails
        let mut pair = TestPair::from_config(&reject_config);
        assert!(pair.handshake().is_err());

        // confirm that overriding the verify_host_callback on connection causes
        // the handshake to succeed
        let mut pair = TestPair::from_config(&reject_config);
        pair.client
            .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;
        pair.server
            .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;
        pair.handshake()?;

        Ok(())
    }

    #[test]
    fn no_client_auth() -> Result<(), Error> {
        use crate::enums::ClientAuthType;

        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_auth_type(ClientAuthType::None)?;
            config.build()?
        };

        let mut pair = TestPair::from_config(&config);
        pair.handshake()?;

        for conn in [pair.server, pair.client] {
            assert!(!conn.client_cert_used());
            let cert = conn.client_cert_chain_bytes()?;
            assert!(cert.is_none());
            let sig_alg = conn.selected_client_signature_algorithm()?;
            assert!(sig_alg.is_none());
            let hash_alg = conn.selected_client_hash_algorithm()?;
            assert!(hash_alg.is_none());
        }

        Ok(())
    }

    #[test]
    fn client_auth() -> Result<(), Error> {
        use crate::enums::ClientAuthType;

        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_auth_type(ClientAuthType::Optional)?;
            config.build()?
        };

        let mut pair = TestPair::from_config(&config);
        pair.handshake()?;

        let cert = pair.server.client_cert_chain_bytes()?;
        assert!(cert.is_some());
        assert!(!cert.unwrap().is_empty());

        for conn in [pair.server, pair.client] {
            assert!(conn.client_cert_used());
            let sig_alg = conn.selected_client_signature_algorithm()?;
            assert!(sig_alg.is_some());
            let hash_alg = conn.selected_client_hash_algorithm()?;
            assert!(hash_alg.is_some());
        }

        Ok(())
    }

    #[test]
    fn system_certs_loaded_by_default() -> Result<(), Error> {
        let keypair = CertKeyPair::default();

        // Load the server certificate into the trust store by overriding the OpenSSL default
        // certificate location.
        temp_env::with_var("SSL_CERT_FILE", Some(keypair.cert_path()), || {
            let mut builder = Builder::new();
            builder
                .load_pem(keypair.cert(), keypair.key())?
                .set_security_policy(&security::DEFAULT_TLS13)?
                .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;

            let config = builder.build().unwrap();
            TestPair::handshake_with_config(&config)?;
            Ok(())
        })
    }

    #[test]
    fn disable_loading_system_certs() -> Result<(), Error> {
        let keypair = CertKeyPair::default();

        // Load the server certificate into the trust store by overriding the OpenSSL default
        // certificate location.
        temp_env::with_var("SSL_CERT_FILE", Some(keypair.cert_path()), || {
            // Test the Builder itself, and also the Builder produced by the Config builder() API.
            for mut builder in [Builder::new(), Config::builder()] {
                builder
                    .load_pem(keypair.cert(), keypair.key())?
                    .set_security_policy(&security::DEFAULT_TLS13)?
                    .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;

                // Disable loading system certificates
                builder.with_system_certs(false)?;

                let config = builder.build()?;
                let mut config_with_system_certs = config.clone();

                // System certificates should not be loaded into the trust store. The handshake
                // should fail since the certificate should not be trusted.
                assert!(TestPair::handshake_with_config(&config).is_err());

                // The handshake should succeed after trusting the certificate.
                unsafe {
                    s2n_tls_sys::s2n_config_load_system_certs(
                        config_with_system_certs.as_mut_ptr(),
                    );
                }
                TestPair::handshake_with_config(&config_with_system_certs)?;
            }
            Ok(())
        })
    }

    #[test]
    fn peer_chain() -> Result<(), Error> {
        use crate::enums::ClientAuthType;

        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_auth_type(ClientAuthType::Optional)?;
            config.build()?
        };

        let mut pair = TestPair::from_config(&config);
        pair.handshake()?;

        for conn in [pair.server, pair.client] {
            let chain = conn.peer_cert_chain()?;
            assert_eq!(chain.len(), 1);
            for cert in chain.iter() {
                let cert = cert?;
                let cert = cert.der()?;
                assert!(!cert.is_empty());
            }
        }

        Ok(())
    }

    #[test]
    fn selected_cert() -> Result<(), Error> {
        use crate::enums::ClientAuthType;

        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_auth_type(ClientAuthType::Required)?;
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
    fn master_secret_success() -> Result<(), Error> {
        let policy = security::Policy::from_version("test_all_tls12")?;
        let config = config_builder(&policy)?.build()?;
        let mut pair = TestPair::from_config(&config);
        pair.handshake()?;

        let server_secret = pair.server.master_secret()?;
        let client_secret = pair.client.master_secret()?;
        assert_eq!(server_secret, client_secret);

        Ok(())
    }

    #[test]
    fn master_secret_failure() -> Result<(), Error> {
        // TLS1.3 does not support getting the master secret
        let mut pair = TestPair::from_config(&build_config(&security::DEFAULT_TLS13)?);
        pair.handshake()?;

        for conn in [pair.client, pair.server] {
            let err = conn.master_secret().unwrap_err();
            assert_eq!(err.kind(), ErrorType::UsageError);
        }

        Ok(())
    }

    #[cfg(feature = "unstable-ktls")]
    #[test]
    fn key_updates() -> Result<(), Error> {
        use crate::{connection::KeyUpdateCount, enums::PeerKeyUpdate};

        let empty_key_updates = KeyUpdateCount {
            recv_key_updates: 0,
            send_key_updates: 0,
        };

        let mut pair = TestPair::from_config(&build_config(&security::DEFAULT_TLS13)?);
        pair.handshake()?;

        // there haven't been any key updates at the start of the connection
        assert_eq!(pair.client.key_update_counts()?, empty_key_updates);
        assert_eq!(pair.server.key_update_counts()?, empty_key_updates);

        pair.server
            .request_key_update(PeerKeyUpdate::KeyUpdateNotRequested)?;
        assert!(pair.server.poll_send(&[0]).is_ready());

        // the server send key has been updated
        let client_updates = pair.client.key_update_counts()?;
        assert_eq!(client_updates, empty_key_updates);
        let server_updates = pair.server.key_update_counts()?;
        assert_eq!(server_updates.recv_key_updates, 0);
        assert_eq!(server_updates.send_key_updates, 1);

        Ok(())
    }

    #[cfg(feature = "fips")]
    #[test]
    fn test_fips_mode() {
        use crate::init;

        init::init();
        assert!(init::fips_mode().unwrap().is_enabled());
    }

    /// Test that a context can be used from within a callback.
    #[test]
    fn test_app_context_callback() -> Result<(), crate::error::Error> {
        struct TestApplicationContext {
            invoked_count: u32,
        }

        struct TestClientHelloHandler {}

        impl ClientHelloCallback for TestClientHelloHandler {
            fn on_client_hello(
                &self,
                connection: &mut connection::Connection,
            ) -> ConnectionFutureResult {
                let app_context = connection
                    .application_context_mut::<TestApplicationContext>()
                    .unwrap();
                app_context.invoked_count += 1;
                Ok(None)
            }
        }

        let config = {
            let keypair = CertKeyPair::default();
            let mut builder = Builder::new();
            builder
                .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
                .unwrap();
            builder
                .set_client_hello_callback(TestClientHelloHandler {})
                .unwrap();
            builder.load_pem(keypair.cert(), keypair.key()).unwrap();
            builder.trust_pem(keypair.cert()).unwrap();
            builder.build().unwrap()
        };
        let mut pair = TestPair::from_config(&config);
        pair.server.set_waker(Some(&noop_waker()))?;

        let context = TestApplicationContext { invoked_count: 0 };
        pair.server.set_application_context(context);

        pair.handshake()?;

        let context = pair
            .server
            .application_context::<TestApplicationContext>()
            .unwrap();
        assert_eq!(context.invoked_count, 1);

        Ok(())
    }

    #[test]
    fn no_application_protocol() -> Result<(), Error> {
        let config = config_builder(&security::DEFAULT)?.build()?;
        let mut pair = TestPair::from_config(&config);
        pair.handshake()?;
        assert!(pair.server.application_protocol().is_none());
        Ok(())
    }

    #[test]
    fn application_protocol() -> Result<(), Error> {
        let config = config_builder(&security::DEFAULT)?.build()?;
        let mut pair = TestPair::from_config(&config);
        pair.server
            .set_application_protocol_preference(["http/1.1", "h2"])?;
        pair.client.append_application_protocol_preference(b"h2")?;
        pair.handshake()?;
        let protocol = pair.server.application_protocol().unwrap();
        assert_eq!(protocol, b"h2");
        Ok(())
    }

    #[test]
    fn client_hello_sslv2_negative() -> Result<(), testing::Error> {
        let config = testing::build_config(&security::DEFAULT_TLS13)?;
        let mut pair = TestPair::from_config(&config);
        pair.handshake()?;
        assert!(!pair.server.client_hello_is_sslv2()?);
        Ok(())
    }

    #[test]
    fn client_hello_sslv2_positive() -> Result<(), testing::Error> {
        // copy-pasted from s2n-tls/tests/testlib/s2n_sslv2_client_hello.h
        // by concatenating these fields together, a valid SSLv2 formatted client hello
        // can be assembled
        const SSLV2_CLIENT_HELLO_HEADER: &[u8] = &[0x80, 0xb3, 0x01, 0x03, 0x03];
        const SSLV2_CLIENT_HELLO_PREFIX: &[u8] = &[0x00, 0x8a, 0x00, 0x00, 0x00, 0x20];
        const SSLV2_CLIENT_HELLO_CIPHER_SUITES: &[u8] = &[
            0x00, 0xc0, 0x24, 0x00, 0xc0, 0x28, 0x00, 0x00, 0x3d, 0x00, 0xc0, 0x26, 0x00, 0xc0,
            0x2a, 0x00, 0x00, 0x6b, 0x00, 0x00, 0x6a, 0x00, 0xc0, 0x0a, 0x07, 0x00, 0xc0, 0x00,
            0xc0, 0x14, 0x00, 0x00, 0x35, 0x00, 0xc0, 0x05, 0x00, 0xc0, 0x0f, 0x00, 0x00, 0x39,
            0x00, 0x00, 0x38, 0x00, 0xc0, 0x23, 0x00, 0xc0, 0x27, 0x00, 0x00, 0x3c, 0x00, 0xc0,
            0x25, 0x00, 0xc0, 0x29, 0x00, 0x00, 0x67, 0x00, 0x00, 0x40, 0x00, 0xc0, 0x09, 0x06,
            0x00, 0x40, 0x00, 0xc0, 0x13, 0x00, 0x00, 0x2f, 0x00, 0xc0, 0x04, 0x01, 0x00, 0x80,
            0x00, 0xc0, 0x0e, 0x00, 0x00, 0x33, 0x00, 0x00, 0x32, 0x00, 0xc0, 0x2c, 0x00, 0xc0,
            0x2b, 0x00, 0xc0, 0x30, 0x00, 0x00, 0x9d, 0x00, 0xc0, 0x2e, 0x00, 0xc0, 0x32, 0x00,
            0x00, 0x9f, 0x00, 0x00, 0xa3, 0x00, 0xc0, 0x2f, 0x00, 0x00, 0x9c, 0x00, 0xc0, 0x2d,
            0x00, 0xc0, 0x31, 0x00, 0x00, 0x9e, 0x00, 0x00, 0xa2, 0x00, 0x00, 0xff,
        ];
        const SSLV2_CLIENT_HELLO_CHALLENGE: &[u8] = &[
            0x5b, 0xe9, 0xcc, 0xad, 0xd6, 0xa5, 0x20, 0xac, 0xa3, 0xf4, 0x8e, 0x88, 0x06, 0xb5,
            0x95, 0x53, 0x2d, 0x53, 0xfe, 0xd7, 0xa1, 0x00, 0x57, 0xc0, 0x53, 0x9d, 0x84, 0x71,
            0x80, 0x7f, 0x30, 0x7e,
        ];

        let config = testing::build_config(&security::Policy::from_version("test_all")?)?;
        // we use the pair to setup IO, but we don't want the client to write anything.
        // So we drop the client and just directly write the SSLv2 header to the
        // client_tx_stream
        let mut pair = TestPair::from_config(&config);
        drop(pair.client);

        let mut client_tx_stream = pair.io.client_tx_stream.borrow_mut();
        client_tx_stream.write_all(SSLV2_CLIENT_HELLO_HEADER)?;
        client_tx_stream.write_all(SSLV2_CLIENT_HELLO_PREFIX)?;
        client_tx_stream.write_all(SSLV2_CLIENT_HELLO_CIPHER_SUITES)?;
        client_tx_stream.write_all(SSLV2_CLIENT_HELLO_CHALLENGE)?;
        // end the exclusive borrow
        drop(client_tx_stream);

        // the first server.poll_negotiate causes the server to read in the client hello
        assert!(pair.server.poll_negotiate()?.is_pending());
        assert!(pair.server.client_hello_is_sslv2()?);
        Ok(())
    }
}
