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
    fn new_sync() -> (Self, Arc<AtomicU64>, Option<Receiver<SendableCertValidationInfo>>) {
        let invoked = Arc::new(AtomicU64::new(0));
        (
            Self {
                invoked: Arc::clone(&invoked),
                immediately_accept: true,
                callback_sender: None,
            },
            invoked,
            None,
        )
    }

    fn new_async() -> (Self, Arc<AtomicU64>, Receiver<SendableCertValidationInfo>) {
        let invoked = Arc::new(AtomicU64::new(0));
        let (tx, rx) = std::sync::mpsc::channel();
        (
            Self {
                invoked: Arc::clone(&invoked),
                immediately_accept: false,
                callback_sender: Some(tx),
            },
            invoked,
            rx,
        )
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
            sender
                .send(SendableCertValidationInfo(info.as_ptr()))
                .expect("sending CertValidationInfo ptr");
        }

        Ok(if self.immediately_accept { Some(true) } else { None })
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

// ---------- Small helpers ----------

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
            let (cb, invoked, _) = TestCertValidationCallback::new_sync();
            builder.set_cert_validation_callback(cb).unwrap();
            (Some(invoked), None)
        }
        MtlsServerCallback::Async => {
            let (cb, invoked, rx) = TestCertValidationCallback::new_async();
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

// ---------- Core test logic ----------

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

/// Drive handshake to the point where async cert validation is pending and
/// the callback has been invoked exactly once.
fn drive_until_async_pending<C, S>(
    client_cfg: &C::Config,
    server_cfg: &S::Config,
    handle: &Arc<AtomicU64>,
) -> TlsConnPair<C, S>
where
    C: TlsConnection,
    S: TlsConnection,
{
    let mut pair = TlsConnPair::<C, S>::from_configs(client_cfg, server_cfg);
    pair.io.enable_recording();

    // ClientHello
    pair.client.handshake().unwrap();
    // ServerHello + server cert flight (1.2 or 1.3 depending on config)
    pair.server.handshake().unwrap();
    // client cert + finished flight
    pair.client.handshake().unwrap();

    // callback has not fired yet
    assert_eq!(handle.load(Ordering::SeqCst), 0);

    // server processes client cert → async callback fires and returns None
    pair.server.handshake().unwrap();
    assert_eq!(handle.load(Ordering::SeqCst), 1);

    // second call should not re-invoke callback
    pair.server.handshake().unwrap();
    assert_eq!(handle.load(Ordering::SeqCst), 1);

    pair
}

// TLS 1.3: bug shows up after accept, when we try to finish the handshake.
fn test_mtls_async_callback_tls13_core<C, S>(
    client_cfg: &C::Config,
    server_cfg: &S::Config,
    handle: Arc<AtomicU64>,
    rx: Receiver<SendableCertValidationInfo>,
) where
    C: TlsConnection,
    S: TlsConnection,
{
    let mut pair = drive_until_async_pending::<C, S>(client_cfg, server_cfg, &handle);

    let ptr = rx.recv().expect("recv CertValidationInfo ptr").0;
    // SAFETY: The pointer comes from the cert validation callback which guarantees
    // it points to a valid s2n_cert_validation_info owned by s2n-tls
    let mut info = unsafe { CertValidationInfo::from_ptr(ptr) };
    info.accept().unwrap();

    // BUG (TLS 1.3): currently hangs here due to multi-message + error blinding.
    pair.handshake().unwrap();

    pair.round_trip_assert(10).unwrap();
    pair.shutdown().unwrap();
}

// TLS 1.2: bug shows up when we drive more handshake *while* validation is pending.
fn test_mtls_async_callback_tls12_core<C, S>(
    client_cfg: &C::Config,
    server_cfg: &S::Config,
    handle: Arc<AtomicU64>,
    rx: Receiver<SendableCertValidationInfo>,
) where
    C: TlsConnection,
    S: TlsConnection,
{
    let mut pair = drive_until_async_pending::<C, S>(client_cfg, server_cfg, &handle);

    // BUG (TLS 1.2): currently hangs here due to multi-message + error blinding.
    pair.handshake().unwrap();

    // Intended flow once bug is fixed:
    let ptr = rx.recv().expect("recv CertValidationInfo ptr").0;
    // SAFETY: The pointer comes from the cert validation callback which guarantees
    // it points to a valid s2n_cert_validation_info owned by s2n-tls
    let mut info = unsafe { CertValidationInfo::from_ptr(ptr) };
    info.accept().unwrap();

    pair.handshake().unwrap();
    pair.round_trip_assert(10).unwrap();
    pair.shutdown().unwrap();
}

// ---------- Tests ----------

// TLS 1.2 tests (run on all libcrypto versions including OpenSSL 1.0.2)

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

// TLS 1.3 tests (require TLS 1.3 support, not available in OpenSSL 1.0.2)

#[test]
fn rustls_s2n_mtls_basic_tls13() {
    crate::capability_check::required_capability(&[crate::capability_check::Capability::Tls13], || {
        let client = rustls_mtls_client(MtlsClientConfig::default());
        let (server, _, _) = s2n_mtls_server(MtlsServerConfig::default());
        test_mtls_basic::<RustlsConnection, S2NConnection>(&client, &server);
    });
}

#[test]
fn rustls_s2n_mtls_sync_callback_tls13() {
    crate::capability_check::required_capability(&[crate::capability_check::Capability::Tls13], || {
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
    });
}

// Async callback tests - currently hang due to error blinding bug, kept as ignored

// TLS 1.3 async mTLS – currently hangs; ignored until bug is fixed.
// As of 2024-11-24: This test hangs because error blinding wipes buffered messages
// when async cert validation returns None. Once the C library is fixed to preserve
// messages during async validation, remove the #[ignore] attribute.
#[test]
#[ignore = "Hangs due to multi-message bug in async cert validation (TLS 1.3)"]
fn rustls_s2n_mtls_async_callback_tls13() {
    crate::capability_check::required_capability(&[crate::capability_check::Capability::Tls13], || {
        let client = rustls_mtls_client(MtlsClientConfig::default());
        let (server, handle, rx) = s2n_mtls_server(MtlsServerConfig {
            callback_mode: MtlsServerCallback::Async,
            ..Default::default()
        });

        test_mtls_async_callback_tls13_core::<RustlsConnection, S2NConnection>(
            &client,
            &server,
            handle.expect("async callback handle"),
            rx.expect("async callback receiver"),
        );
    });
}

// TLS 1.2 async mTLS – same multi-message bug; ignored until bug is fixed.
// As of 2024-11-24: This test hangs because error blinding wipes buffered messages
// when async cert validation returns None. Once the C library is fixed to preserve
// messages during async validation, remove the #[ignore] attribute.
#[test]
#[ignore = "Hangs due to multi-message bug in async cert validation (TLS 1.2)"]
fn rustls_s2n_mtls_async_callback_tls12() {
    let client = rustls_mtls_client(MtlsClientConfig {
        tls_version: &rustls::version::TLS12,
        ..MtlsClientConfig::default()
    });

    let (server, handle, rx) = s2n_mtls_server(MtlsServerConfig {
        callback_mode: MtlsServerCallback::Async,
        ..Default::default()
    });

    test_mtls_async_callback_tls12_core::<RustlsConnection, S2NConnection>(
        &client,
        &server,
        handle.expect("async callback handle"),
        rx.expect("async callback receiver"),
    );
}

#[test]
fn s2n_s2n_mtls_async_callback() {
    let client = s2n_mtls_client(MtlsClientConfig::default());
    let (server, handle, rx) = s2n_mtls_server(MtlsServerConfig {
        callback_mode: MtlsServerCallback::Async,
        with_hostname_verifier: true,
        ..Default::default()
    });

    // This follows the TLS 1.3 flow by default (client cfg defaults to TLS 1.3).
    test_mtls_async_callback_tls13_core::<S2NConnection, S2NConnection>(
        &client,
        &server,
        handle.expect("async callback handle"),
        rx.expect("async callback receiver"),
    );
}
