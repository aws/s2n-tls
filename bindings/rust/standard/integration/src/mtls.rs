// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use rustls::ClientConfig;
use s2n_tls::{
    callbacks::{CertValidationCallback, CertValidationInfo, VerifyHostNameCallback},
    connection::Connection,
    enums::ClientAuthType,
    error::Error as S2NError,
};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc::{Receiver, Sender},
    Arc,
};
use tls_harness::{
    cohort::{RustlsConfig, RustlsConnection, S2NConfig, S2NConnection},
    harness::{read_to_bytes, TlsConfigBuilder},
    PemType, SigType, TlsConnPair, TlsConnection,
};

/// Total application data size (chosen so the final record is always more than small size)
const APP_DATA_SIZE: usize = 100_000;


struct SendableCertValidationInfo(*mut s2n_tls_sys::s2n_cert_validation_info);
unsafe impl Send for SendableCertValidationInfo {}

/// A test callback that can operate in sync or async mode.
///
/// This callback is used to test certificate validation during the TLS handshake.
/// It can operate in two modes:
///
/// - **Sync mode**: Immediately accepts the certificate (returns `Some(true)`)
/// - **Async mode**: Defers the decision (returns `None`) and sends the validation
///   info pointer through a channel so the test can manually accept/reject later
#[derive(Debug)]
struct TestCertValidationCallback {
    invoked: Arc<AtomicU64>,
    immediately_accept: bool,
    callback_sender: Option<Sender<SendableCertValidationInfo>>,
}

impl TestCertValidationCallback {
    /// Create a callback that immediately accepts certificates (sync mode)
    fn new_sync() -> Self {
        Self {
            invoked: Default::default(),
            immediately_accept: true,
            callback_sender: None, // No channel needed for sync mode
        }
    }

    /// Create a callback that defers the decision (async mode)
    /// 
    /// Returns the callback and a receiver that will get the validation info pointer
    /// when the callback is invoked during the handshake.
    fn new_async() -> (Self, Receiver<SendableCertValidationInfo>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let callback = Self {
            invoked: Default::default(),
            immediately_accept: false,
            callback_sender: Some(tx),
        };
        (callback, rx)
    }
}

impl CertValidationCallback for TestCertValidationCallback {
    /// Called by s2n-tls during the handshake when a client certificate is received.
    ///
    /// Return value:
    /// - `Ok(Some(true))`: Accept the certificate immediately (sync mode)
    /// - `Ok(None)`: Defer the decision - the test must call accept()/reject() later (async mode)
    fn handle_validation(
        &self,
        _conn: &mut Connection,
        info: &mut CertValidationInfo,
    ) -> Result<Option<bool>, S2NError> {
        self.invoked.fetch_add(1, Ordering::SeqCst);
        
        if let Some(sender) = &self.callback_sender {
            sender
                .send(SendableCertValidationInfo(info.info.as_ptr()))
                .unwrap();
        }

        if self.immediately_accept {
            Ok(Some(true))
        } else {
            Ok(None)
        }
    }
}

/// A hostname verifier that accepts all hostnames.
///
/// Hostname verification isn't the focus of the test so we ignore it.
struct HostNameIgnorer;
impl VerifyHostNameCallback for HostNameIgnorer {
    fn verify_host_name(&self, _host_name: &str) -> bool {
        true // Accept any hostname
    }
}

struct MtlsClientConfig {
    /// The signature algorithm type (RSA2048, ECDSA256, etc.)
    sig_type: SigType,
}

impl Default for MtlsClientConfig {
    fn default() -> Self {
        Self {
            sig_type: SigType::Rsa2048,
        }
    }
}

enum MtlsServerCallback {
    None,
    Sync,
    Async,
}

/// Configuration for mTLS server.
///
/// Specifies the server's certificate and optionally a custom cert validation callback.
struct MtlsServerConfig {
    sig_type: SigType,
    callback_mode: MtlsServerCallback,
}

impl Default for MtlsServerConfig {
    fn default() -> Self {
        Self {
            sig_type: SigType::Rsa2048,
            callback_mode: MtlsServerCallback::None, // No custom callback by default
        }
    }
}



/// Basic mTLS test: handshake, data transfer, and shutdown.
fn test_mtls_basic<C, S>(client_config: &C::Config, server_config: &S::Config)
where
    C: TlsConnection,
    S: TlsConnection,
{
    let mut pair = TlsConnPair::<C, S>::from_configs(client_config, server_config);
    pair.handshake().unwrap();
    pair.round_trip_assert(APP_DATA_SIZE).unwrap();
    pair.shutdown().unwrap();
}

/// mTLS test with synchronous cert validation callback.
///
/// This test verifies that a custom certificate validation callback is invoked
/// during the handshake and can immediately accept or reject the client certificate.
fn test_mtls_sync_callback<C, S>(
    client_config: &C::Config,
    server_config: &S::Config,
    callback_handle: Arc<AtomicU64>,
) where
    C: TlsConnection,
    S: TlsConnection,
{
    let mut pair = TlsConnPair::<C, S>::from_configs(client_config, server_config);
    assert_eq!(callback_handle.load(Ordering::SeqCst), 0);
    pair.handshake().unwrap();
    assert_eq!(callback_handle.load(Ordering::SeqCst), 1);

    pair.round_trip_assert(APP_DATA_SIZE).unwrap();
    pair.shutdown().unwrap();
}

/// mTLS test with asynchronous cert validation callback.
///
/// This test verifies that certificate validation can be deferred - the callback
/// returns "false" to indicate validation is pending, and the test manually calls
/// accept() or reject() later to complete the handshake and verify the cert asynchronously.
fn test_mtls_async_callback<C, S>(
    client_config: &C::Config,
    server_config: &S::Config,
    callback_handle: Arc<AtomicU64>,
    rx: Receiver<SendableCertValidationInfo>,
) where
    C: TlsConnection,
    S: TlsConnection,
{
    let mut pair = TlsConnPair::<C, S>::from_configs(client_config, server_config);
    pair.io.enable_recording();

    // Step through handshake manually to control when validation happens
    // Client sends ClientHello
    pair.client.handshake().unwrap();
    
    // Server responds with ServerHello, Certificate, etc.
    pair.server.handshake().unwrap();
    
    // Client sends Certificate, CertificateVerify, Finished
    pair.client.handshake().unwrap();
    
    // Callback hasn't been invoked yet (server hasn't processed client cert)
    assert_eq!(callback_handle.load(Ordering::SeqCst), 0);
    
    // Server processes client certificate - this triggers the callback
    // The callback returns false (async mode), so validation is pending
    pair.server.handshake().unwrap();
    
    // Verify callback was invoked exactly once
    assert_eq!(callback_handle.load(Ordering::SeqCst), 1);
    
    // Calling handshake again should NOT invoke the callback again
    // (validation is still pending from the first invocation)
    pair.server.handshake().unwrap();
    assert_eq!(callback_handle.load(Ordering::SeqCst), 1);

    // Now manually accept the certificate (this is the "async" part)
    // Receive the validation info pointer that was sent through the channel
    let ptr = rx.recv().unwrap().0;
    let mut validation_info = CertValidationInfo::from_ptr(ptr);
    
    // Accept the certificate - this unblocks the handshake
    validation_info.accept().unwrap();

    // Complete the handshake now that validation is done
    pair.handshake().unwrap();
    
    // Verify the connection works
    pair.round_trip_assert(10).unwrap();
    pair.shutdown().unwrap();
}

/// Create a Rustls client configured for mTLS.
fn create_rustls_mtls_client_config(config: MtlsClientConfig) -> RustlsConfig {
    let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    
    let client_config = ClientConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(RustlsConfig::get_root_cert_store(config.sig_type))
        .with_client_auth_cert(
            RustlsConfig::get_cert_chain(PemType::ClientCertChain, config.sig_type),
            RustlsConfig::get_key(PemType::ClientKey, config.sig_type),
        )
        .unwrap();

    client_config.into()
}


/// Create an S2N server configured for mTLS with optional cert validation callback.
fn create_s2n_mtls_server_config(
    config: MtlsServerConfig,
) -> (
    S2NConfig,
    Option<Arc<AtomicU64>>,
    Option<Receiver<SendableCertValidationInfo>>,
) {
    let mut server_config = s2n_tls::config::Builder::new();
    
    // Load the server's certificate and private key
    server_config.set_chain(config.sig_type);
    
    server_config
        // Require client to present a certificate
        .set_client_auth_type(ClientAuthType::Required)
        .unwrap()
        // Don't load system CA certificates (use only our test CA)
        .with_system_certs(false)
        .unwrap()
        // Load the test CA certificate to verify client certificates
        .trust_pem(&read_to_bytes(PemType::CACert, config.sig_type))
        .unwrap();

    // Optionally install a custom cert validation callback
    let (callback_handle, rx) = match config.callback_mode {
        MtlsServerCallback::None => {
            (None, None)
        }
        MtlsServerCallback::Sync => {
            let callback = TestCertValidationCallback::new_sync();
            let handle = Arc::clone(&callback.invoked);
            server_config
                .set_cert_validation_callback(callback)
                .unwrap();
            (Some(handle), None)
        }
        MtlsServerCallback::Async => {
            let (callback, rx) = TestCertValidationCallback::new_async();
            let handle = Arc::clone(&callback.invoked);
            server_config
                .set_cert_validation_callback(callback)
                .unwrap();
            (Some(handle), Some(rx))
        }
    };

    let server_config = S2NConfig::from(server_config.build().unwrap());
    (server_config, callback_handle, rx)
}


/// Test basic mTLS with Rustls client and S2N server.
#[test]
fn rustls_s2n_mtls_basic() {
    let client_config = create_rustls_mtls_client_config(MtlsClientConfig::default());
    
    let (server_config, _, _) = create_s2n_mtls_server_config(MtlsServerConfig::default());

    test_mtls_basic::<RustlsConnection, S2NConnection>(&client_config, &server_config);
}

/// Test mTLS with synchronous cert validation callback.
#[test]
fn rustls_s2n_mtls_sync_callback() {
    let client_config = create_rustls_mtls_client_config(MtlsClientConfig::default());
    
    // Create S2N server with a synchronous validation callback
    let (server_config, callback_handle, _) = create_s2n_mtls_server_config(MtlsServerConfig {
        callback_mode: MtlsServerCallback::Sync,
        ..Default::default()
    });
    
    // Run the sync callback test
    test_mtls_sync_callback::<RustlsConnection, S2NConnection>(
        &client_config,
        &server_config,
        callback_handle.unwrap(),
    );
}

/// Test mTLS with asynchronous cert validation callback.
///
#[test]
fn rustls_s2n_mtls_async_callback() {
    let client_config = create_rustls_mtls_client_config(MtlsClientConfig::default());
    
    // Create S2N server with an asynchronous validation callback
    let (server_config, callback_handle, rx) = create_s2n_mtls_server_config(MtlsServerConfig {
        callback_mode: MtlsServerCallback::Async,
        ..Default::default()
    });
    
    // Run the async callback test
    test_mtls_async_callback::<RustlsConnection, S2NConnection>(
        &client_config,
        &server_config,
        callback_handle.unwrap(),
        rx.unwrap(),
    );
}

/// Create an S2N client configured for mTLS.
/// - Requires explicit client auth type setting
fn create_s2n_mtls_client_config(config: MtlsClientConfig) -> S2NConfig {
    let mut client_config = s2n_tls::config::Builder::new();

    client_config.set_chain(config.sig_type);
    
    client_config
        .set_client_auth_type(ClientAuthType::Required)
        .unwrap()
        .with_system_certs(false)
        .unwrap()
        .trust_pem(&read_to_bytes(PemType::CACert, config.sig_type))
        .unwrap()
        .set_verify_host_callback(HostNameIgnorer)
        .unwrap();
    
    S2NConfig::from(client_config.build().unwrap())
}

/// Create an S2N server with hostname verifier (for S2N-to-S2N tests).
fn create_s2n_mtls_server_config_with_hostname_verifier(
    config: MtlsServerConfig,
) -> (
    S2NConfig,
    Option<Arc<AtomicU64>>,
    Option<Receiver<SendableCertValidationInfo>>,
) {
    let mut server_config = s2n_tls::config::Builder::new();
    
    server_config.set_chain(config.sig_type);
    
    server_config
        .set_client_auth_type(ClientAuthType::Required)
        .unwrap()
        .with_system_certs(false)
        .unwrap()
        .trust_pem(&read_to_bytes(PemType::CACert, config.sig_type))
        .unwrap()
        .set_verify_host_callback(HostNameIgnorer)
        .unwrap();

    let (callback_handle, rx) = match config.callback_mode {
        MtlsServerCallback::None => (None, None),
        MtlsServerCallback::Sync => {
            let callback = TestCertValidationCallback::new_sync();
            let handle = Arc::clone(&callback.invoked);
            server_config
                .set_cert_validation_callback(callback)
                .unwrap();
            (Some(handle), None)
        }
        MtlsServerCallback::Async => {
            let (callback, rx) = TestCertValidationCallback::new_async();
            let handle = Arc::clone(&callback.invoked);
            server_config
                .set_cert_validation_callback(callback)
                .unwrap();
            (Some(handle), Some(rx))
        }
    };

    let server_config = S2NConfig::from(server_config.build().unwrap());
    (server_config, callback_handle, rx)
}

/// Test mTLS with asynchronous cert validation using S2N for both client and server.
#[test]
fn s2n_s2n_mtls_async_callback() {
    let client_config = create_s2n_mtls_client_config(MtlsClientConfig::default());
    
    let (server_config, callback_handle, rx) =
        create_s2n_mtls_server_config_with_hostname_verifier(MtlsServerConfig {
            callback_mode: MtlsServerCallback::Async,
            ..Default::default()
        });
    
    test_mtls_async_callback::<S2NConnection, S2NConnection>(
        &client_config,
        &server_config,
        callback_handle.unwrap(),
        rx.unwrap(),
    );
}