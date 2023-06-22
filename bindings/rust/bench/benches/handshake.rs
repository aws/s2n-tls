// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{
    CipherSuite::*, CryptoConfig, ECGroup::*, OpenSslHarness, RustlsHarness, S2NHarness,
    TlsBenchHarness,
};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

pub fn bench_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");

    macro_rules! bench_handshake_for_libraries {
        ($(($lib_name:expr, $lib_type:ty),)*) => {
        $(
            // generate all inputs (TlsBenchHarness structs) before benchmarking handshakes
            // timing only includes negotiation, not config/connection initialization
            group.bench_function($lib_name, |b| {
                b.iter_batched_ref(
                    || <$lib_type>::default().unwrap(),
                    |harness| {
                        harness.handshake().unwrap();
                    },
                    BatchSize::SmallInput,
                )
            });
        )*
        }
    }

    bench_handshake_for_libraries! {
        ("s2n-tls", S2NHarness),
        ("rustls", RustlsHarness),
        ("openssl", OpenSslHarness),
    }

    group.finish();
}

pub fn bench_handshake_key_exchange(c: &mut Criterion) {
    macro_rules! bench_handshake_for_libraries {
        ($ec_group:ident, $(($lib_name:expr, $lib_type:ty),)*) => {
            // separate out each cipher_suite/ec_group pair to different groups
            let mut group = c.benchmark_group(format!("handshake-{:?}", $ec_group));
            $(
                // generate all inputs (TlsBenchHarness structs) before benchmarking handshakes
                // timing only includes negotiation, not config/connection initialization
                group.bench_function($lib_name, |b| {
                    b.iter_batched_ref(
                        || <$lib_type>::new(&CryptoConfig { cipher_suite: AES_128_GCM_SHA256, $ec_group }).unwrap(),
                        |harness| {
                            harness.handshake().unwrap();
                        },
                        BatchSize::SmallInput,
                    )
                });
            )*
            group.finish();
        }
    }

    for ec_group in [SECP256R1, X25519] {
        bench_handshake_for_libraries! {
            ec_group,
            ("s2n-tls", S2NHarness),
            ("rustls", RustlsHarness),
            ("openssl", OpenSslHarness),
        }
    }
}

criterion_group!(benches, bench_handshake, bench_handshake_key_exchange);
criterion_main!(benches);
