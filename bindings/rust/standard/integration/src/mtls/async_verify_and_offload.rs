// Copyright Amazon.com, Inc. or its affiliates.
// SPDX-License-Identifier: Apache-2.0

// mTLS async verify + async offload test
// This is a "stress test" of our mTLS async callback which configures:
// - rustls client (TLS 1.3)
// - s2n-tls server
// - async certificate validation callback
// - async offload operation (pkey verify)

use super::*;
use s2n_tls_sys::{
    s2n_async_offload_op, s2n_async_offload_op_perform, s2n_async_offload_op_type,
    s2n_config_set_async_offload_callback,
};
use std::ffi::c_void;

/// A wrapper around a raw pointer to `s2n_async_offload_op` that can be sent across threads.
///
/// This is used in tests to simulate async offload operations where the operation
/// is deferred and performed on a different thread or after some async operation.
struct SendableAsyncOffloadOp(*mut s2n_async_offload_op);

// SAFETY: The pointer is owned by s2n-tls and remains valid for the duration of the
// pending async offload operation (until perform() is called, or freed).
// The test mimics the intended usage pattern where an application hands off the pointer
// to a worker thread that later performs the operation.
unsafe impl Send for SendableAsyncOffloadOp {}

// Async offload context for C FFI
struct AsyncOffloadCtx {
    invoked: Arc<AtomicU64>,
    sender: Sender<SendableAsyncOffloadOp>,
}

// C-style async offload callback
unsafe extern "C" fn test_async_offload_cb(
    _conn: *mut s2n_connection,
    op: *mut s2n_async_offload_op,
    ctx: *mut c_void,
) -> i32 {
    let ctx = unsafe { &*(ctx as *mut AsyncOffloadCtx) };

    ctx.invoked.fetch_add(1, Ordering::SeqCst);
    ctx.sender.send(SendableAsyncOffloadOp(op)).unwrap();

    s2n_status_code::SUCCESS
}

/// Registers an async pkey verify offload callback and returns (invoked_counter, operation_receiver).
fn register_async_pkey_verify_offload(
    s2n_cfg: &mut S2NConfig,
) -> (Arc<AtomicU64>, Receiver<SendableAsyncOffloadOp>) {
    let invoked = Arc::new(AtomicU64::new(0));
    let (tx, rx) = std::sync::mpsc::channel();

    let ctx = Box::new(AsyncOffloadCtx {
        invoked: Arc::clone(&invoked),
        sender: tx,
    });
    let ctx_ptr = Box::into_raw(ctx) as *mut c_void;

    // SAFETY: s2n stores this context pointer and later returns it in the async
    // callback. Because s2n never frees it, we intentionally leak the Box so the
    // memory stays valid for the lifetime of the config (test-only).
    unsafe {
        let raw = raw_config(s2n_cfg);
        let allowed_types = s2n_async_offload_op_type::OFFLOAD_PKEY_VERIFY;

        let result = s2n_config_set_async_offload_callback(
            raw,
            allowed_types,
            Some(test_async_offload_cb),
            ctx_ptr,
        );
        assert_eq!(
            result,
            s2n_status_code::SUCCESS,
            "s2n_config_set_async_offload_callback failed"
        );
    }

    (invoked, rx)
}

/// rustls client and s2n-tls server with async cert validation and async pkey
/// verify offload over TLS 1.3.
#[test]
fn s2n_server_tls13() {
    crate::capability_check::required_capability(
        &[crate::capability_check::Capability::Tls13],
        || {
            let client = rustls_mtls_client(SigType::Rsa2048, &rustls::version::TLS13);

            let (server, cert_invoked, cert_rx, offload_invoked, offload_rx) = {
                let builder = s2n_mtls_base_builder(SigType::Rsa2048);
                let mut s2n_cfg = S2NConfig::from(builder.build().unwrap());

                let (cert_invoked, cert_rx) = register_async_cert_callback(&mut s2n_cfg);
                let (offload_invoked, offload_rx) =
                    register_async_pkey_verify_offload(&mut s2n_cfg);

                (s2n_cfg, cert_invoked, cert_rx, offload_invoked, offload_rx)
            };

            let mut pair =
                TlsConnPair::<RustlsConnection, S2NConnection>::from_configs(&client, &server);

            // Drive early handshake messages (ClientHello, ServerHello, EncryptedExtensions)
            pair.client.handshake().unwrap();
            pair.server.handshake().unwrap();

            // Progress until just before client Certificate is processed:
            pair.client.handshake().unwrap();
            assert_eq!(cert_invoked.load(Ordering::SeqCst), 0);
            assert_eq!(offload_invoked.load(Ordering::SeqCst), 0);

            // Server processes client Certificate -> async cert validation fires
            pair.server.handshake().unwrap();
            assert_eq!(cert_invoked.load(Ordering::SeqCst), 1);

            let cert_ptr = cert_rx.recv().unwrap().0;
            unsafe {
                let rc = s2n_cert_validation_accept(cert_ptr);
                assert_eq!(rc, 0, "s2n_cert_validation_accept failed");
            }

            // Continue server handshake: async offload for pkey verify fires
            pair.server.handshake().unwrap();
            assert_eq!(offload_invoked.load(Ordering::SeqCst), 1);

            let SendableAsyncOffloadOp(offload_op_ptr) = offload_rx.recv().unwrap();
            unsafe {
                let rc = s2n_async_offload_op_perform(offload_op_ptr);
                assert_eq!(rc, 0, "s2n_async_offload_op_perform failed");
            }

            pair.handshake().unwrap();
            pair.round_trip_assert(10).unwrap();
            pair.shutdown().unwrap();
        },
    );
}
