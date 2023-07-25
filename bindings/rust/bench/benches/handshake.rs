// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{
    CryptoConfig,
    ECGroup::{self, *},
    HandshakeType::{self, *},
    OpenSslHarness, RustlsHarness, S2NHarness, TlsBenchHarness,
};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, Criterion,
};

pub fn bench_handshake_params(c: &mut Criterion) {
    fn bench_handshake_for_library<T: TlsBenchHarness>(
        bench_group: &mut BenchmarkGroup<WallTime>,
        name: &str,
        handshake_type: HandshakeType,
        ec_group: ECGroup,
    ) {
        // generate all harnesses (TlsBenchHarness structs) beforehand so that benchmarks
        // only include negotiation and not config/connection initialization
        bench_group.bench_function(name, |b| {
            b.iter_batched_ref(
                || {
                    T::new(
                        CryptoConfig {
                            cipher_suite: Default::default(),
                            ec_group,
                        },
                        handshake_type,
                        Default::default(),
                    )
                },
                |harness| {
                    // harnesses with certain parameters fail to initialize for
                    // some past versions of s2n-tls, but missing data can be
                    // visually interpolated in the historical performance graph
                    if let Ok(harness) = harness {
                        let _ = harness.handshake();
                    }
                },
                BatchSize::SmallInput,
            )
        });
    }

    for handshake_type in [ServerAuth, MutualAuth] {
        for ec_group in [SECP256R1, X25519] {
            let mut bench_group =
                c.benchmark_group(format!("handshake-{:?}-{:?}", handshake_type, ec_group));

            bench_handshake_for_library::<S2NHarness>(
                &mut bench_group,
                "s2n-tls",
                handshake_type,
                ec_group,
            );
            #[cfg(not(feature = "historical-perf"))]
            {
                bench_handshake_for_library::<RustlsHarness>(
                    &mut bench_group,
                    "rustls",
                    handshake_type,
                    ec_group,
                );
                bench_handshake_for_library::<OpenSslHarness>(
                    &mut bench_group,
                    "openssl",
                    handshake_type,
                    ec_group,
                );
            }
        }
    }
}

criterion_group!(benches, bench_handshake_params);
criterion_main!(benches);
