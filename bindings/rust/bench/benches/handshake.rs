// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{
    CipherSuite::*,
    CryptoConfig,
    ECGroup::{self, *},
    OpenSslHarness, RustlsHarness, S2NHarness, TlsBenchHarness,
};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, Criterion,
};

pub fn bench_handshake_key_exchange(c: &mut Criterion) {
    fn bench_handshake_for_library<T: TlsBenchHarness>(
        bench_group: &mut BenchmarkGroup<WallTime>,
        name: &str,
        ec_group: ECGroup,
    ) {
        // generate all inputs (TlsBenchHarness structs) before benchmarking handshakes
        // timing only includes negotiation, not config/connection initialization
        bench_group.bench_function(name, |b| {
            b.iter_batched_ref(
                || {
                    T::new(&CryptoConfig {
                        cipher_suite: AES_256_GCM_SHA384,
                        ec_group,
                    })
                },
                |harness| {
                    // if harness invalid, do nothing but don't panic
                    // useful for historical performance bench to ignore configs
                    // invalid only for past versions of s2n-tls
                    if let Ok(harness) = harness {
                        let _ = harness.handshake();
                    }
                },
                BatchSize::SmallInput,
            )
        });
    }

    for ec_group in [SECP256R1, X25519] {
        let mut bench_group = c.benchmark_group(format!("handshake-{:?}", ec_group));
        bench_handshake_for_library::<S2NHarness>(&mut bench_group, "s2n-tls", ec_group);
        #[cfg(not(feature = "s2n-only"))]
        {
            bench_handshake_for_library::<RustlsHarness>(&mut bench_group, "rustls", ec_group);
            bench_handshake_for_library::<OpenSslHarness>(&mut bench_group, "openssl", ec_group);
        }
    }
}

criterion_group!(benches, bench_handshake_key_exchange);
criterion_main!(benches);
