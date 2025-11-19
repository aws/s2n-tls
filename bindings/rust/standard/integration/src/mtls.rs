// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use rustls::ClientConfig;
use s2n_tls::{
    callbacks::{CertValidationCallbackSync, CertValidationInfo, VerifyHostNameCallback},
    connection::Connection,
    enums::ClientAuthType,
};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc::{Receiver, Sender},
    Arc,
};
use tls_harness::{
    cohort::{
        rustls::RustlsConfigBuilder, RustlsConfig, RustlsConnection, S2NConfig, S2NConnection,
    },
    harness::{read_to_bytes, TlsConfigBuilder, TlsConfigBuilderPair},
    PemType, SigType, TlsConnPair, TlsConnection,
};

/// Total application data size (chosen so the final record is always more than small size)
const APP_DATA_SIZE: usize = 100_000;

#[test]
fn mtls_basic() {
    let mut pair: TlsConnPair<RustlsConnection, S2NConnection> = {
        let mut server_config = s2n_tls::config::Builder::new();
        server_config.set_chain(SigType::Rsa2048);
        server_config
            .set_client_auth_type(ClientAuthType::Required)
            .unwrap();
        server_config.with_system_certs(false).unwrap();
        server_config
            .trust_pem(&read_to_bytes(PemType::CACert, SigType::Rsa2048))
            .unwrap();
        let server_config = server_config.build().unwrap();
        let server_config = S2NConfig::from(server_config);

        let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let client_config = ClientConfig::builder_with_provider(crypto_provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(RustlsConfig::get_root_cert_store(SigType::Rsa2048))
            .with_client_auth_cert(
                RustlsConfig::get_cert_chain(PemType::ClientCertChain, SigType::Rsa2048),
                RustlsConfig::get_key(PemType::ClientKey, SigType::Rsa2048),
            )
            .unwrap();
        let client_config: RustlsConfig = client_config.into();

        let mut configs =
            TlsConfigBuilderPair::<RustlsConfigBuilder, s2n_tls::config::Builder>::default();
        configs
            .server
            .set_client_auth_type(ClientAuthType::Required)
            .unwrap();
        TlsConnPair::from_configs(&client_config, &server_config)
    };

    pair.handshake().unwrap();
    pair.round_trip_assert(APP_DATA_SIZE).unwrap();
    pair.shutdown().unwrap();
}
use s2n_tls::error::Error as S2NError;

/// Wrapper to make the raw cert validation info pointer sendable across threads
struct SendableCertValidationInfo(*mut s2n_tls_sys::s2n_cert_validation_info);

unsafe impl Send for SendableCertValidationInfo {}

#[derive(Debug)]
struct SyncCallback {
    invoked: Arc<AtomicU64>,
    /// this is the number of time that the callback must be polled before it returns successfully
    immediately_accept: bool,
    callback_sender: Sender<SendableCertValidationInfo>,
}

impl SyncCallback {
    fn new(immediately_accept: bool) -> (Self, Receiver<SendableCertValidationInfo>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let value = Self {
            invoked: Default::default(),
            immediately_accept: immediately_accept,
            callback_sender: tx
        };
        (value, rx)
    }
}

impl CertValidationCallbackSync for SyncCallback {
    fn handle_validation(&self, _conn: &mut Connection, info: &mut CertValidationInfo) -> Result<bool, S2NError> {
        self.invoked.fetch_add(1, Ordering::SeqCst);
        self.callback_sender
            .send(SendableCertValidationInfo(info.info.as_ptr()))
            .unwrap();
        
        // Return true to accept, false for async validation
        // The wrapper in config.rs will call info.accept() or info.reject() based on this return value
        // Do NOT call info.accept() or info.reject() here - it will be called by the wrapper
        Ok(self.immediately_accept)
    }
}

#[test]
fn mtls_with_cert_verify() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();
    let (callback, _rx) = SyncCallback::new(true);
    let callback_handle = Arc::clone(&callback.invoked);
    let mut pair: TlsConnPair<RustlsConnection, S2NConnection> = {
        let server_config = {
            let mut server_config = s2n_tls::config::Builder::new();
            server_config.set_chain(SigType::Rsa2048);
            server_config
                .set_client_auth_type(ClientAuthType::Required)
                .unwrap()
                .with_system_certs(false)
                .unwrap()
                .trust_pem(&read_to_bytes(PemType::CACert, SigType::Rsa2048))
                .unwrap()
                .set_cert_validation_callback_sync(callback)
                .unwrap();
            let server_config = server_config.build().unwrap();
            S2NConfig::from(server_config)
        };

        let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let client_config = ClientConfig::builder_with_provider(crypto_provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(RustlsConfig::get_root_cert_store(SigType::Rsa2048))
            .with_client_auth_cert(
                RustlsConfig::get_cert_chain(PemType::ClientCertChain, SigType::Rsa2048),
                RustlsConfig::get_key(PemType::ClientKey, SigType::Rsa2048),
            )
            .unwrap();
        let client_config: RustlsConfig = client_config.into();

        let mut configs =
            TlsConfigBuilderPair::<RustlsConfigBuilder, s2n_tls::config::Builder>::default();
        configs
            .server
            .set_client_auth_type(ClientAuthType::Required)
            .unwrap();
        TlsConnPair::from_configs(&client_config, &server_config)
    };
    assert_eq!(callback_handle.load(Ordering::SeqCst), 0);

    pair.handshake().unwrap();
    pair.round_trip_assert(APP_DATA_SIZE).unwrap();
    pair.shutdown().unwrap();

    assert_eq!(callback_handle.load(Ordering::SeqCst), 1);
}

// gdb --args target/debug/deps/integration-a4a2dc78ba29c050 mtls_rustls_s2n_async_verify
#[test]
fn mtls_rustls_s2n_async_verify() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();
    let (callback, rx) = SyncCallback::new(false);
    let callback_handle = Arc::clone(&callback.invoked);
    let mut pair: TlsConnPair<RustlsConnection, S2NConnection> = {
        let server_config = {
            let mut server_config = s2n_tls::config::Builder::new();
            server_config.set_chain(SigType::Rsa2048);
            server_config
                .set_client_auth_type(ClientAuthType::Required)
                .unwrap()
                .with_system_certs(false)
                .unwrap()
                .trust_pem(&read_to_bytes(PemType::CACert, SigType::Rsa2048))
                .unwrap()
                .set_cert_validation_callback_sync(callback)
                .unwrap();
            let server_config = server_config.build().unwrap();
            S2NConfig::from(server_config)
        };

        let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let client_config = ClientConfig::builder_with_provider(crypto_provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(RustlsConfig::get_root_cert_store(SigType::Rsa2048))
            .with_client_auth_cert(
                RustlsConfig::get_cert_chain(PemType::ClientCertChain, SigType::Rsa2048),
                RustlsConfig::get_key(PemType::ClientKey, SigType::Rsa2048),
            )
            .unwrap();
        let client_config: RustlsConfig = client_config.into();

        TlsConnPair::from_configs(&client_config, &server_config)
    };
    pair.io.enable_recording();

    pair.client.handshake().unwrap();
    pair.server.handshake().unwrap();
    pair.client.handshake().unwrap();
    assert_eq!(callback_handle.load(Ordering::SeqCst), 0);
    pair.server.handshake().unwrap();
    assert_eq!(callback_handle.load(Ordering::SeqCst), 1);
    pair.server.handshake().unwrap();
    assert_eq!(callback_handle.load(Ordering::SeqCst), 1);

    let ptr = rx.recv().unwrap().0;
    let mut validation_info = CertValidationInfo::from_ptr(ptr);
    validation_info.accept().unwrap();
    tracing::info!("cert accepted");
    pair.handshake().unwrap();

    pair.round_trip_assert(10).unwrap();
    pair.shutdown().unwrap();
}

struct HostNameIgnorer;
impl VerifyHostNameCallback for HostNameIgnorer {
    fn verify_host_name(&self, host_name: &str) -> bool {
        println!("the host name: {host_name}");
        true
    }
}

/// control case: async cert validation stuff works in this case
#[test]
fn mtls_s2n_s2n_async_verify() {
    let (callback, rx) = SyncCallback::new(false);
    let callback_handle = Arc::clone(&callback.invoked);
    let mut pair: TlsConnPair<S2NConnection, S2NConnection> = {
        let mut configs =
            TlsConfigBuilderPair::<s2n_tls::config::Builder, s2n_tls::config::Builder>::default();
        configs
            .server
            .set_client_auth_type(ClientAuthType::Required)
            .unwrap()
            .with_system_certs(false)
            .unwrap()
            .trust_pem(&read_to_bytes(PemType::CACert, SigType::Rsa2048))
            .unwrap()
            .set_cert_validation_callback_sync(callback)
            .unwrap()
            .set_verify_host_callback(HostNameIgnorer)
            .unwrap();
        configs.client.set_chain(SigType::Rsa2048);
        configs
            .client
            .set_client_auth_type(ClientAuthType::Required)
            .unwrap()
            .set_verify_host_callback(HostNameIgnorer)
            .unwrap();

        configs.connection_pair()
    };
    pair.io.enable_recording();

    pair.client.handshake().unwrap();
    pair.server.handshake().unwrap();
    pair.client.handshake().unwrap();
    assert_eq!(callback_handle.load(Ordering::SeqCst), 0);
    pair.server.handshake().unwrap();
    assert_eq!(callback_handle.load(Ordering::SeqCst), 1);
    let ptr = rx.recv().unwrap().0;
    let mut validation_info = CertValidationInfo::from_ptr(ptr);
    validation_info.accept().unwrap();

    pair.handshake().unwrap();

    pair.round_trip_assert(10).unwrap();
    pair.shutdown().unwrap();

}