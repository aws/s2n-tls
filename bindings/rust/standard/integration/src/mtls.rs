// Copyright Amazon.com, Inc. or its affiliates.
// SPDX-License-Identifier: Apache-2.0

// This test suite exercises mTLS interoperability between s2n-tls and rustls,
// including:
//   - basic mTLS handshakes (TLS 1.2 and 1.3)
//   - sync certificate validation callbacks
//   - async certificate validation callbacks wired directly via the C FFI
//
// Async callbacks are registered via s2n_tls_sys instead of the Rust bindings
// to avoid exposing an unstable async callback API in the public Rust surface.

use std::{
    mem,
    os::raw::c_void,
    ptr::NonNull,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{Receiver, Sender},
        Arc,
    },
};

use rustls::ClientConfig;

use s2n_tls::{
    callbacks::{CertValidationCallbackSync, CertValidationInfo, VerifyHostNameCallback},
    config::{Builder, Config},
    connection::Connection,
    enums::ClientAuthType,
    error::Error as S2NError,
};

use s2n_tls_sys::{
    s2n_cert_validation_accept, s2n_cert_validation_info, s2n_config,
    s2n_config_set_cert_validation_cb, s2n_connection, s2n_status_code,
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
struct SendableCertValidationInfo(*mut s2n_cert_validation_info);

// SAFETY: The pointer is owned by s2n-tls and remains valid for the duration of the
// pending async validation (until accept() or reject() is called, or the connection is freed).
// The test mimics the intended usage pattern where an application hands off the pointer
// to a worker thread that later calls accept()/reject().
unsafe impl Send for SendableCertValidationInfo {}

/// Get the raw s2n_config pointer from S2NConfig
/// SAFETY: S2NConfig wraps Config, which is a thin NonNull<s2n_config>
/// wrapper. This is test-only functionality relying on that internal layout.
unsafe fn raw_config(cfg: &mut S2NConfig) -> *mut s2n_config {
    let config: &mut Config = &mut cfg.config;
    let nn: &mut NonNull<s2n_config> = mem::transmute(config);
    nn.as_ptr()
}

#[derive(Debug)]
struct TestCertValidationCallback {
    invoked: Arc<AtomicU64>,
    immediately_accept: bool,
}

impl TestCertValidationCallback {
    fn new_sync() -> Self {
        Self {
            invoked: Arc::new(AtomicU64::new(0)),
            immediately_accept: true,
        }
    }

    fn invoked_count(&self) -> &Arc<AtomicU64> {
        &self.invoked
    }
}

impl CertValidationCallbackSync for TestCertValidationCallback {
    fn handle_validation(
        &self,
        _conn: &mut Connection,
        _info: &mut CertValidationInfo,
    ) -> Result<bool, S2NError> {
        self.invoked.fetch_add(1, Ordering::SeqCst);
        Ok(self.immediately_accept)
    }
}

// Async callback context for C FFI
struct AsyncCertCtx {
    invoked: Arc<AtomicU64>,
    sender: Sender<SendableCertValidationInfo>,
}

// C-style async cert validation callback
extern "C" fn test_async_cert_cb(
    _conn: *mut s2n_connection,
    info: *mut s2n_cert_validation_info,
    ctx: *mut c_void,
) -> i32 {
    let ctx = unsafe { &*(ctx as *mut AsyncCertCtx) };

    ctx.invoked.fetch_add(1, Ordering::SeqCst);
    ctx.sender
        .send(SendableCertValidationInfo(info))
        .expect("send async cert validation info");

    s2n_status_code::SUCCESS
}

#[derive(Default)]
struct HostNameIgnorer;
impl VerifyHostNameCallback for HostNameIgnorer {
    fn verify_host_name(&self, _host_name: &str) -> bool {
        true
    }
}

/// Creates a base s2n-tls builder configured for mTLS.
fn s2n_mtls_base_builder(sig_type: SigType) -> Builder {
    let mut builder = Builder::new();
    builder.set_chain(sig_type);
    builder
        .set_client_auth_type(ClientAuthType::Required)
        .unwrap()
        .with_system_certs(false)
        .unwrap()
        .trust_pem(&read_to_bytes(PemType::CACert, sig_type))
        .unwrap()
        .set_verify_host_callback(HostNameIgnorer)
        .unwrap();
    builder
}

/// Helper which registers an async cert validation callback via C FFI
fn register_async_cert_callback(
    s2n_cfg: &mut S2NConfig,
) -> (Arc<AtomicU64>, Receiver<SendableCertValidationInfo>) {
    let invoked = Arc::new(AtomicU64::new(0));
    let (tx, rx) = std::sync::mpsc::channel();

    let ctx = Box::new(AsyncCertCtx {
        invoked: Arc::clone(&invoked),
        sender: tx,
    });
    let ctx_ptr = Box::into_raw(ctx) as *mut c_void;

    // SAFETY: s2n stores this context pointer and later returns it in the async
    // callback. Because s2n never frees it, we intentionally leak the Box so the
    // memory stays valid for the lifetime of the config (test-only).
    unsafe {
        let raw = raw_config(s2n_cfg);
        let rc = s2n_config_set_cert_validation_cb(raw, Some(test_async_cert_cb), ctx_ptr);
        assert_eq!(
            rc,
            s2n_status_code::SUCCESS,
            "s2n_config_set_cert_validation_cb failed"
        );
    }

    (invoked, rx)
}

/// Builds a rustls mTLS client config for the given TLS version.
fn rustls_mtls_client(
    sig_type: SigType,
    tls_version: &'static rustls::SupportedProtocolVersion,
) -> RustlsConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[tls_version])
        .unwrap()
        .with_root_certificates(RustlsConfig::get_root_cert_store(sig_type))
        .with_client_auth_cert(
            RustlsConfig::get_cert_chain(PemType::ClientCertChain, sig_type),
            RustlsConfig::get_key(PemType::ClientKey, sig_type),
        )
        .unwrap();
    client.into()
}

/// Builds a rustls mTLS server config for the given TLS version.
fn rustls_mtls_server(
    sig_type: SigType,
    tls_version: &'static rustls::SupportedProtocolVersion,
) -> RustlsConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_cert_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(
        RustlsConfig::get_root_cert_store(sig_type),
    ))
    .build()
    .unwrap();

    let server = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[tls_version])
        .unwrap()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(
            RustlsConfig::get_cert_chain(PemType::ServerCertChain, sig_type),
            RustlsConfig::get_key(PemType::ServerKey, sig_type),
        )
        .unwrap();
    server.into()
}

// ============================================================================
// Basic mTLS tests
// ============================================================================

// Helper for basic test case
fn test_basic<C, S>(client_cfg: &C::Config, server_cfg: &S::Config)
where
    C: TlsConnection,
    S: TlsConnection,
{
    let mut pair = TlsConnPair::<C, S>::from_configs(client_cfg, server_cfg);
    pair.handshake().unwrap();
    pair.round_trip_assert(APP_DATA_SIZE).unwrap();
    pair.shutdown().unwrap();
}

// s2n client, rustls server
#[test]
fn s2n_client_basic() {
    // TLS 1.2
    let client = {
        let builder = s2n_mtls_base_builder(SigType::Rsa2048);
        S2NConfig::from(builder.build().unwrap())
    };
    let server = rustls_mtls_server(SigType::Rsa2048, &rustls::version::TLS12);
    test_basic::<S2NConnection, RustlsConnection>(&client, &server);

    // TLS 1.3
    crate::capability_check::required_capability(
        &[crate::capability_check::Capability::Tls13],
        || {
            let client = {
                let builder = s2n_mtls_base_builder(SigType::Rsa2048);
                S2NConfig::from(builder.build().unwrap())
            };
            let server = rustls_mtls_server(SigType::Rsa2048, &rustls::version::TLS13);
            test_basic::<S2NConnection, RustlsConnection>(&client, &server);
        },
    );
}

// rustls client, s2n server
#[test]
fn s2n_server_basic() {
    // TLS 1.2
    let client = rustls_mtls_client(SigType::Rsa2048, &rustls::version::TLS12);
    let server = {
        let builder = s2n_mtls_base_builder(SigType::Rsa2048);
        S2NConfig::from(builder.build().unwrap())
    };
    test_basic::<RustlsConnection, S2NConnection>(&client, &server);

    // TLS 1.3
    crate::capability_check::required_capability(
        &[crate::capability_check::Capability::Tls13],
        || {
            let client = rustls_mtls_client(SigType::Rsa2048, &rustls::version::TLS13);
            let server = {
                let builder = s2n_mtls_base_builder(SigType::Rsa2048);
                S2NConfig::from(builder.build().unwrap())
            };
            test_basic::<RustlsConnection, S2NConnection>(&client, &server);
        },
    );
}

// ============================================================================
// Sync callback tests
// ============================================================================

// Helper for synchronous callback tests
fn test_sync_callback<C, S>(client_cfg: &C::Config, server_cfg: &S::Config, handle: Arc<AtomicU64>)
where
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

// s2n client with sync callback, rustls server
#[test]
fn s2n_client_sync_callback() {
    // TLS 1.2
    let (client, handle) = {
        let mut builder = s2n_mtls_base_builder(SigType::Rsa2048);
        let cb = TestCertValidationCallback::new_sync();
        let invoked = Arc::clone(cb.invoked_count());
        builder.set_cert_validation_callback_sync(cb).unwrap();
        (S2NConfig::from(builder.build().unwrap()), invoked)
    };
    let server = rustls_mtls_server(SigType::Rsa2048, &rustls::version::TLS12);
    test_sync_callback::<S2NConnection, RustlsConnection>(&client, &server, handle);

    // TLS 1.3
    crate::capability_check::required_capability(
        &[crate::capability_check::Capability::Tls13],
        || {
            let (client, handle) = {
                let mut builder = s2n_mtls_base_builder(SigType::Rsa2048);
                let cb = TestCertValidationCallback::new_sync();
                let invoked = Arc::clone(cb.invoked_count());
                builder.set_cert_validation_callback_sync(cb).unwrap();
                (S2NConfig::from(builder.build().unwrap()), invoked)
            };
            let server = rustls_mtls_server(SigType::Rsa2048, &rustls::version::TLS13);

            test_sync_callback::<S2NConnection, RustlsConnection>(&client, &server, handle);
        },
    );
}

// rustls client, s2n server with sync callback
#[test]
fn s2n_server_sync_callback() {
    // TLS 1.2
    let client = rustls_mtls_client(SigType::Rsa2048, &rustls::version::TLS12);
    let (server, handle) = {
        let mut builder = s2n_mtls_base_builder(SigType::Rsa2048);
        let cb = TestCertValidationCallback::new_sync();
        let invoked = Arc::clone(cb.invoked_count());
        builder.set_cert_validation_callback_sync(cb).unwrap();
        (S2NConfig::from(builder.build().unwrap()), invoked)
    };

    test_sync_callback::<RustlsConnection, S2NConnection>(&client, &server, handle);

    // TLS 1.3
    crate::capability_check::required_capability(
        &[crate::capability_check::Capability::Tls13],
        || {
            let client = rustls_mtls_client(SigType::Rsa2048, &rustls::version::TLS13);
            let (server, handle) = {
                let mut builder = s2n_mtls_base_builder(SigType::Rsa2048);
                let cb = TestCertValidationCallback::new_sync();
                let invoked = Arc::clone(cb.invoked_count());
                builder.set_cert_validation_callback_sync(cb).unwrap();
                (S2NConfig::from(builder.build().unwrap()), invoked)
            };

            test_sync_callback::<RustlsConnection, S2NConnection>(&client, &server, handle);
        },
    );
}

// ============================================================================
// Async callback tests
// ============================================================================

// Helper for async server-side cert validation tests.
fn test_async_server_callback<C, S>(
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

    pair.client.handshake().unwrap();
    pair.server.handshake().unwrap();
    pair.client.handshake().unwrap();

    assert_eq!(handle.load(Ordering::SeqCst), 0);
    pair.server.handshake().unwrap();
    assert_eq!(handle.load(Ordering::SeqCst), 1);

    let ptr = rx.recv().expect("recv CertValidationInfo ptr").0;

    // SAFETY: Pointer from cert validation callback, valid until accept/reject called.
    unsafe {
        let rc = s2n_cert_validation_accept(ptr);
        assert_eq!(rc, 0, "s2n_cert_validation_accept failed");
    }

    pair.handshake().unwrap();
    pair.round_trip_assert(10).unwrap();
    pair.shutdown().unwrap();
    pair
}

// Helper for async client-side cert validation tests.
fn test_async_client_callback<C, S>(
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

    pair.client.handshake().unwrap();
    pair.server.handshake().unwrap();

    assert_eq!(handle.load(Ordering::SeqCst), 0);
    pair.client.handshake().unwrap();
    assert_eq!(handle.load(Ordering::SeqCst), 1);

    let ptr = rx.recv().expect("recv CertValidationInfo ptr").0;

    // SAFETY: Pointer from cert validation callback, valid until accept/reject called.
    unsafe {
        let rc = s2n_cert_validation_accept(ptr);
        assert_eq!(rc, 0, "s2n_cert_validation_accept failed");
    }

    pair.handshake().unwrap();
    pair.round_trip_assert(10).unwrap();
    pair.shutdown().unwrap();
    pair
}

// As of 2025-11-24: s2n as client (TLS 1.2, 1.3) and s2n as
// server (TLS 1.3) hang due to a multi-message async cert validation bug.
// s2n incorrectly clears queued handshake messages, causing
// poll_negotiate() to spin forever. Remove #[ignore] once fixed.
// s2n client with async callback, rustls server
#[test]
#[ignore = "Hangs due to multi-message bug in async cert validation"]
fn s2n_client_async_callback() {
    // TLS 1.2
    let (client, handle, rx) = {
        let builder = s2n_mtls_base_builder(SigType::Rsa2048);
        let mut s2n_cfg = S2NConfig::from(builder.build().unwrap());
        let (invoked, rx) = register_async_cert_callback(&mut s2n_cfg);
        (s2n_cfg, invoked, rx)
    };
    let server = rustls_mtls_server(SigType::Rsa2048, &rustls::version::TLS12);
    let _pair =
        test_async_client_callback::<S2NConnection, RustlsConnection>(&client, &server, handle, rx);

    // TLS 1.3
    crate::capability_check::required_capability(
        &[crate::capability_check::Capability::Tls13],
        || {
            let (client, handle, rx) = {
                let builder = s2n_mtls_base_builder(SigType::Rsa2048);
                let mut s2n_cfg = S2NConfig::from(builder.build().unwrap());
                let (invoked, rx) = register_async_cert_callback(&mut s2n_cfg);
                (s2n_cfg, invoked, rx)
            };
            let server = rustls_mtls_server(SigType::Rsa2048, &rustls::version::TLS13);
            let _pair = test_async_client_callback::<S2NConnection, RustlsConnection>(
                &client, &server, handle, rx,
            );
        },
    );
}

// rustls client, s2n server with async callback
// Rustls TLS 1.2 clients do not send multiple handshake messages in a
// single record, so s2n never hits the multi-message async-callback
// bug that appears in TLS 1.3 but both variants are ignored for now
// for simplicity.
#[test]
#[ignore = "Hangs due to multi-message bug in async cert validation"]
fn s2n_server_async_callback() {
    // TLS 1.2
    let client = rustls_mtls_client(SigType::Rsa2048, &rustls::version::TLS12);
    let (server, handle, rx) = {
        let builder = s2n_mtls_base_builder(SigType::Rsa2048);
        let mut s2n_cfg = S2NConfig::from(builder.build().unwrap());
        let (invoked, rx) = register_async_cert_callback(&mut s2n_cfg);
        (s2n_cfg, invoked, rx)
    };
    let _pair =
        test_async_server_callback::<RustlsConnection, S2NConnection>(&client, &server, handle, rx);

    // TLS 1.3
    crate::capability_check::required_capability(
        &[crate::capability_check::Capability::Tls13],
        || {
            let client = rustls_mtls_client(SigType::Rsa2048, &rustls::version::TLS13);
            let (server, handle, rx) = {
                let builder = s2n_mtls_base_builder(SigType::Rsa2048);
                let mut s2n_cfg = S2NConfig::from(builder.build().unwrap());
                let (invoked, rx) = register_async_cert_callback(&mut s2n_cfg);
                (s2n_cfg, invoked, rx)
            };

            let _pair = test_async_server_callback::<RustlsConnection, S2NConnection>(
                &client, &server, handle, rx,
            );
        },
    );
}

// s2n client, s2n server with async callback
#[test]
fn s2n_s2n_mtls_async_callback() {
    let client = {
        let builder = s2n_mtls_base_builder(SigType::Rsa2048);
        S2NConfig::from(builder.build().unwrap())
    };
    let (server, handle, rx) = {
        let builder = s2n_mtls_base_builder(SigType::Rsa2048);
        let mut s2n_cfg = S2NConfig::from(builder.build().unwrap());
        let (invoked, rx) = register_async_cert_callback(&mut s2n_cfg);
        (s2n_cfg, invoked, rx)
    };

    let _pair =
        test_async_server_callback::<S2NConnection, S2NConnection>(&client, &server, handle, rx);
}
