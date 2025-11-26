// Copyright Amazon.com, Inc. or its affiliates.
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

const APP_DATA_SIZE: usize = 100_000;

/// A wrapper around a raw pointer to `s2n_cert_validation_info` that can be sent across threads.
///
/// This is used in tests to simulate async certificate validation where the validation
/// decision is deferred and made on a different thread or after some async operation.
struct SendableCertValidationInfo(*mut s2n_tls_sys::s2n_cert_validation_info);

// SAFETY: The pointer is owned by s2n-tls and remains valid for the duration of the
// pending async validation (until accept() or reject() is called, or the connection is freed).
// The test mimics the intended usage pattern where an application hands off the pointer
// to a worker thread that later calls accept()/reject().
unsafe impl Send for SendableCertValidationInfo {}

#[derive(Debug)]
struct TestCertValidationCallback {
    invoked: Arc<AtomicU64>,
    immediately_accept: bool,
    callback_sender: Option<Sender<SendableCertValidationInfo>>,
}

impl TestCertValidationCallback {
    fn new_sync() -> Self {
        Self {
            invoked: Arc::new(AtomicU64::new(0)),
            immediately_accept: true,
            callback_sender: None,
        }
    }

    fn new_async() -> (Self, Receiver<SendableCertValidationInfo>) {
        let (tx, rx) = std::sync::mpsc::channel();
        (
            Self {
                invoked: Arc::new(AtomicU64::new(0)),
                immediately_accept: false,
                callback_sender: Some(tx),
            },
            rx,
        )
    }

    fn invoked_count(&self) -> &Arc<AtomicU64> {
        &self.invoked
    }
}

impl CertValidationCallback for TestCertValidationCallback {
    fn handle_validation(
        &self,
        _conn: &mut Connection,
        info: &mut CertValidationInfo,
    ) -> Result<Option<bool>, S2NError> {
        self.invoked.fetch_add(1, Ordering::SeqCst);

        if let Some(sender) = &self.callback_sender {
            // We send a raw pointer to the underlying s2n_cert_validation_info so the test
            // can later reconstruct CertValidationInfo and call accept()/reject().
            sender
                .send(SendableCertValidationInfo(info.as_ptr()))
                .expect("sending CertValidationInfo ptr");
        }

        Ok(if self.immediately_accept {
            Some(true)
        } else {
            None
        })
    }
}

#[derive(Default)]
struct HostNameIgnorer;
impl VerifyHostNameCallback for HostNameIgnorer {
    fn verify_host_name(&self, _host_name: &str) -> bool {
        true
    }
}

#[derive(Clone, Copy)]
struct MtlsClientConfig {
    sig_type: SigType,
    tls_version: &'static rustls::SupportedProtocolVersion,
}

impl Default for MtlsClientConfig {
    fn default() -> Self {
        Self {
            sig_type: SigType::Rsa2048,
            tls_version: &rustls::version::TLS13,
        }
    }
}

#[derive(Clone, Copy, Default)]
enum MtlsServerCallback {
    #[default]
    None,
    Sync,
    Async,
}

#[derive(Clone, Copy, Default)]
struct MtlsServerConfig {
    sig_type: SigType,
    callback_mode: MtlsServerCallback,
    with_hostname_verifier: bool,
}

fn rustls_mtls_client(cfg: MtlsClientConfig) -> RustlsConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[cfg.tls_version])
        .unwrap()
        .with_root_certificates(RustlsConfig::get_root_cert_store(cfg.sig_type))
        .with_client_auth_cert(
            RustlsConfig::get_cert_chain(PemType::ClientCertChain, cfg.sig_type),
            RustlsConfig::get_key(PemType::ClientKey, cfg.sig_type),
        )
        .unwrap();
    client.into()
}

fn rustls_mtls_server(cfg: MtlsClientConfig) -> RustlsConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_cert_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(
        RustlsConfig::get_root_cert_store(cfg.sig_type),
    ))
    .build()
    .unwrap();

    let server = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[cfg.tls_version])
        .unwrap()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(
            RustlsConfig::get_cert_chain(PemType::ServerCertChain, cfg.sig_type),
            RustlsConfig::get_key(PemType::ServerKey, cfg.sig_type),
        )
        .unwrap();
    server.into()
}

fn s2n_mtls_server(
    cfg: MtlsServerConfig,
) -> (
    S2NConfig,
    Option<Arc<AtomicU64>>,
    Option<Receiver<SendableCertValidationInfo>>,
) {
    let mut builder = s2n_tls::config::Builder::new();
    builder.set_chain(cfg.sig_type);
    builder
        .set_client_auth_type(ClientAuthType::Required)
        .unwrap()
        .with_system_certs(false)
        .unwrap()
        .trust_pem(&read_to_bytes(PemType::CACert, cfg.sig_type))
        .unwrap();

    if cfg.with_hostname_verifier {
        builder.set_verify_host_callback(HostNameIgnorer).unwrap();
    }

    let (handle, rx) = match cfg.callback_mode {
        MtlsServerCallback::None => (None, None),
        MtlsServerCallback::Sync => {
            let cb = TestCertValidationCallback::new_sync();
            let invoked = Arc::clone(cb.invoked_count());
            builder.set_cert_validation_callback(cb).unwrap();
            (Some(invoked), None)
        }
        MtlsServerCallback::Async => {
            let (cb, rx) = TestCertValidationCallback::new_async();
            let invoked = Arc::clone(cb.invoked_count());
            builder.set_cert_validation_callback(cb).unwrap();
            (Some(invoked), Some(rx))
        }
    };

    (S2NConfig::from(builder.build().unwrap()), handle, rx)
}

fn s2n_mtls_client(cfg: MtlsClientConfig) -> S2NConfig {
    let mut builder = s2n_tls::config::Builder::new();
    builder.set_chain(cfg.sig_type);
    builder
        .set_client_auth_type(ClientAuthType::Required)
        .unwrap()
        .with_system_certs(false)
        .unwrap()
        .trust_pem(&read_to_bytes(PemType::CACert, cfg.sig_type))
        .unwrap()
        .set_verify_host_callback(HostNameIgnorer)
        .unwrap();
    S2NConfig::from(builder.build().unwrap())
}

fn s2n_mtls_client_with_sync_callback(cfg: MtlsClientConfig) -> (S2NConfig, Arc<AtomicU64>) {
    let mut builder = s2n_tls::config::Builder::new();
    builder.set_chain(cfg.sig_type);
    builder
        .set_client_auth_type(ClientAuthType::Required)
        .unwrap()
        .with_system_certs(false)
        .unwrap()
        .trust_pem(&read_to_bytes(PemType::CACert, cfg.sig_type))
        .unwrap()
        .set_verify_host_callback(HostNameIgnorer)
        .unwrap();

    let cb = TestCertValidationCallback::new_sync();
    let invoked = Arc::clone(cb.invoked_count());
    builder.set_cert_validation_callback(cb).unwrap();

    (S2NConfig::from(builder.build().unwrap()), invoked)
}

fn s2n_mtls_client_with_async_callback(
    cfg: MtlsClientConfig,
) -> (
    S2NConfig,
    Arc<AtomicU64>,
    Receiver<SendableCertValidationInfo>,
) {
    let mut builder = s2n_tls::config::Builder::new();
    builder.set_chain(cfg.sig_type);
    builder
        .set_client_auth_type(ClientAuthType::Required)
        .unwrap()
        .with_system_certs(false)
        .unwrap()
        .trust_pem(&read_to_bytes(PemType::CACert, cfg.sig_type))
        .unwrap()
        .set_verify_host_callback(HostNameIgnorer)
        .unwrap();

    let (cb, rx) = TestCertValidationCallback::new_async();
    let invoked = Arc::clone(cb.invoked_count());
    builder.set_cert_validation_callback(cb).unwrap();

    (S2NConfig::from(builder.build().unwrap()), invoked, rx)
}

fn test_mtls_basic<C, S>(client_cfg: &C::Config, server_cfg: &S::Config)
where
    C: TlsConnection,
    S: TlsConnection,
{
    let mut pair = TlsConnPair::<C, S>::from_configs(client_cfg, server_cfg);
    pair.handshake().unwrap();
    pair.round_trip_assert(APP_DATA_SIZE).unwrap();
    pair.shutdown().unwrap();
}

fn test_mtls_sync_callback<C, S>(
    client_cfg: &C::Config,
    server_cfg: &S::Config,
    handle: Arc<AtomicU64>,
) where
    C: TlsConnection,
    S: TlsConnection,
{
    let mut pair = TlsConnPair::<C, S>::from_configs(client_cfg, server_cfg);
    assert_eq!(handle.load(Ordering::SeqCst), 0);
    pair.handshake().unwrap();
    assert_eq!(handle.load(Ordering::SeqCst), 1);
    pair.round_trip_assert(APP_DATA_SIZE).unwrap();
    pair.shutdown().unwrap();
}

fn test_mtls_async_callback<C, S>(
    client_cfg: &C::Config,
    server_cfg: &S::Config,
    handle: Arc<AtomicU64>,
    rx: Receiver<SendableCertValidationInfo>,
) -> TlsConnPair<C, S>
where
    C: TlsConnection,
    S: TlsConnection,
{
    let mut pair = TlsConnPair::<C, S>::from_configs(client_cfg, server_cfg);
    pair.io.enable_recording();

    pair.client.handshake().unwrap();
    pair.server.handshake().unwrap();
    pair.client.handshake().unwrap();

    assert_eq!(handle.load(Ordering::SeqCst), 0);
    pair.server.handshake().unwrap();
    assert_eq!(handle.load(Ordering::SeqCst), 1);

    let ptr = rx.recv().expect("recv CertValidationInfo ptr").0;
    // SAFETY: Pointer from cert validation callback, valid until accept/reject called
    let mut info = unsafe { CertValidationInfo::from_ptr(ptr) };
    info.accept().unwrap();

    pair.handshake().unwrap();
    pair.round_trip_assert(10).unwrap();
    pair.shutdown().unwrap();
    pair
}

fn test_mtls_async_callback_client<C, S>(
    client_cfg: &C::Config,
    server_cfg: &S::Config,
    handle: Arc<AtomicU64>,
    rx: Receiver<SendableCertValidationInfo>,
) -> TlsConnPair<C, S>
where
    C: TlsConnection,
    S: TlsConnection,
{
    let mut pair = TlsConnPair::<C, S>::from_configs(client_cfg, server_cfg);
    pair.io.enable_recording();

    pair.client.handshake().unwrap();
    pair.server.handshake().unwrap();

    assert_eq!(handle.load(Ordering::SeqCst), 0);
    pair.client.handshake().unwrap();
    assert_eq!(handle.load(Ordering::SeqCst), 1);

    let ptr = rx.recv().expect("recv CertValidationInfo ptr").0;
    // SAFETY: Pointer from cert validation callback, valid until accept/reject called
    let mut info = unsafe { CertValidationInfo::from_ptr(ptr) };
    info.accept().unwrap();

    pair.handshake().unwrap();
    pair.round_trip_assert(10).unwrap();
    pair.shutdown().unwrap();
    pair
}

// ============================================================================
// Basic mTLS tests
// ============================================================================

// s2n client, rustls server
#[test]
fn s2n_rustls_mtls_basic_tls12() {
    let client = s2n_mtls_client(MtlsClientConfig {
        tls_version: &rustls::version::TLS12,
        ..MtlsClientConfig::default()
    });
    let server = rustls_mtls_server(MtlsClientConfig {
        tls_version: &rustls::version::TLS12,
        ..MtlsClientConfig::default()
    });
    test_mtls_basic::<S2NConnection, RustlsConnection>(&client, &server);
}

#[test]
fn s2n_rustls_mtls_basic_tls13() {
    crate::capability_check::required_capability(
        &[crate::capability_check::Capability::Tls13],
        || {
            let client = s2n_mtls_client(MtlsClientConfig::default());
            let server = rustls_mtls_server(MtlsClientConfig::default());
            test_mtls_basic::<S2NConnection, RustlsConnection>(&client, &server);
        },
    );
}

// rustls client, s2n server
#[test]
fn rustls_s2n_mtls_basic_tls12() {
    let client = rustls_mtls_client(MtlsClientConfig {
        tls_version: &rustls::version::TLS12,
        ..MtlsClientConfig::default()
    });
    let (server, _, _) = s2n_mtls_server(MtlsServerConfig::default());
    test_mtls_basic::<RustlsConnection, S2NConnection>(&client, &server);
}

#[test]
fn rustls_s2n_mtls_basic_tls13() {
    crate::capability_check::required_capability(
        &[crate::capability_check::Capability::Tls13],
        || {
            let client = rustls_mtls_client(MtlsClientConfig::default());
            let (server, _, _) = s2n_mtls_server(MtlsServerConfig::default());
            test_mtls_basic::<RustlsConnection, S2NConnection>(&client, &server);
        },
    );
}

// ============================================================================
// Sync callback tests
// ============================================================================

// s2n client with sync callback, rustls server
#[test]
fn s2n_rustls_mtls_sync_callback_tls12() {
    let (client, handle) = s2n_mtls_client_with_sync_callback(MtlsClientConfig {
        tls_version: &rustls::version::TLS12,
        ..MtlsClientConfig::default()
    });
    let server = rustls_mtls_server(MtlsClientConfig {
        tls_version: &rustls::version::TLS12,
        ..MtlsClientConfig::default()
    });

    test_mtls_sync_callback::<S2NConnection, RustlsConnection>(&client, &server, handle);
}

#[test]
fn s2n_rustls_mtls_sync_callback_tls13() {
    crate::capability_check::required_capability(
        &[crate::capability_check::Capability::Tls13],
        || {
            let (client, handle) = s2n_mtls_client_with_sync_callback(MtlsClientConfig::default());
            let server = rustls_mtls_server(MtlsClientConfig::default());

            test_mtls_sync_callback::<S2NConnection, RustlsConnection>(&client, &server, handle);
        },
    );
}

// rustls client, s2n server with sync callback
#[test]
fn rustls_s2n_mtls_sync_callback_tls12() {
    let client = rustls_mtls_client(MtlsClientConfig {
        tls_version: &rustls::version::TLS12,
        ..MtlsClientConfig::default()
    });
    let (server, handle, _) = s2n_mtls_server(MtlsServerConfig {
        callback_mode: MtlsServerCallback::Sync,
        ..Default::default()
    });

    test_mtls_sync_callback::<RustlsConnection, S2NConnection>(
        &client,
        &server,
        handle.expect("sync callback handle"),
    );
}

#[test]
fn rustls_s2n_mtls_sync_callback_tls13() {
    crate::capability_check::required_capability(
        &[crate::capability_check::Capability::Tls13],
        || {
            let client = rustls_mtls_client(MtlsClientConfig::default());
            let (server, handle, _) = s2n_mtls_server(MtlsServerConfig {
                callback_mode: MtlsServerCallback::Sync,
                ..Default::default()
            });

            test_mtls_sync_callback::<RustlsConnection, S2NConnection>(
                &client,
                &server,
                handle.expect("sync callback handle"),
            );
        },
    );
}

// ============================================================================
// Async callback tests
// ============================================================================

// As of 2025-11-24: s2n as client (TLS 1.2, 1.3) and s2n as
// server (TLS 1.3) hang due to a multi-message async cert validation bug.
// s2n incorrectly clears queued handshake messages, causing
// poll_negotiate() to spin forever. Remove #[ignore] once fixed.
// s2n client with async callback, rustls server
#[test]
#[ignore = "Hangs due to multi-message bug in async cert validation"]
fn s2n_rustls_mtls_async_callback_tls12() {
    let (client, handle, rx) = s2n_mtls_client_with_async_callback(MtlsClientConfig {
        tls_version: &rustls::version::TLS12,
        ..MtlsClientConfig::default()
    });

    let server = rustls_mtls_server(MtlsClientConfig {
        tls_version: &rustls::version::TLS12,
        ..MtlsClientConfig::default()
    });

    let _pair = test_mtls_async_callback_client::<S2NConnection, RustlsConnection>(
        &client, &server, handle, rx,
    );
}

#[test]
#[ignore = "Hangs due to multi-message bug in async cert validation"]
fn s2n_rustls_mtls_async_callback_tls13() {
    crate::capability_check::required_capability(
        &[crate::capability_check::Capability::Tls13],
        || {
            let (client, handle, rx) =
                s2n_mtls_client_with_async_callback(MtlsClientConfig::default());

            let server = rustls_mtls_server(MtlsClientConfig::default());

            let _pair = test_mtls_async_callback_client::<S2NConnection, RustlsConnection>(
                &client, &server, handle, rx,
            );
        },
    );
}

// rustls client, s2n server with async callback
// Rustls TLS 1.2 clients do not send multiple handshake messages in a
// single record, so s2n never hits the multi-message async-callback
// bug that appears in TLS 1.3
#[test]
fn rustls_s2n_mtls_async_callback_tls12() {
    let client = rustls_mtls_client(MtlsClientConfig {
        tls_version: &rustls::version::TLS12,
        ..MtlsClientConfig::default()
    });

    let (server, handle, rx) = s2n_mtls_server(MtlsServerConfig {
        callback_mode: MtlsServerCallback::Async,
        ..Default::default()
    });

    let _pair = test_mtls_async_callback::<RustlsConnection, S2NConnection>(
        &client,
        &server,
        handle.expect("async callback handle"),
        rx.expect("async callback receiver"),
    );
}

#[test]
#[ignore = "Hangs due to multi-message bug in async cert validation"]
fn rustls_s2n_mtls_async_callback_tls13() {
    crate::capability_check::required_capability(
        &[crate::capability_check::Capability::Tls13],
        || {
            let client = rustls_mtls_client(MtlsClientConfig::default());
            let (server, handle, rx) = s2n_mtls_server(MtlsServerConfig {
                callback_mode: MtlsServerCallback::Async,
                ..Default::default()
            });

            let _pair = test_mtls_async_callback::<RustlsConnection, S2NConnection>(
                &client,
                &server,
                handle.expect("async callback handle"),
                rx.expect("async callback receiver"),
            );
        },
    );
}

// s2n client, s2n server with async callback
#[test]
fn s2n_s2n_mtls_async_callback() {
    let client = s2n_mtls_client(MtlsClientConfig::default());
    let (server, handle, rx) = s2n_mtls_server(MtlsServerConfig {
        callback_mode: MtlsServerCallback::Async,
        with_hostname_verifier: true,
        ..Default::default()
    });

    let _pair = test_mtls_async_callback::<S2NConnection, S2NConnection>(
        &client,
        &server,
        handle.expect("async callback handle"),
        rx.expect("async callback receiver"),
    );
}
