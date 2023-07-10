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
use std::any::type_name;

pub fn bench_handshake_params(c: &mut Criterion) {
    fn bench_handshake_for_library<T: TlsBenchHarness>(
        bench_group: &mut BenchmarkGroup<WallTime>,
        handshake_type: HandshakeType,
        ec_group: ECGroup,
    ) {
        bench_group.bench_function(type_name::<T>(), |b| {
            b.iter_batched_ref(
                || {
                    T::new(
                        CryptoConfig {
                            cipher_suite: Default::default(),
                            ec_group,
                        },
                        handshake_type,
                    )
                    .unwrap()
                },
                |harness| {
                    harness.handshake().unwrap();
                },
                BatchSize::SmallInput,
            )
        });
    }

    for handshake_type in [ServerAuth, MutualAuth] {
        for ec_group in [SECP256R1, X25519] {
            let mut bench_group =
                c.benchmark_group(format!("handshake-{:?}-{:?}", handshake_type, ec_group));
            bench_handshake_for_library::<S2NHarness>(&mut bench_group, handshake_type, ec_group);
            bench_handshake_for_library::<RustlsHarness>(
                &mut bench_group,
                handshake_type,
                ec_group,
            );
            bench_handshake_for_library::<OpenSslHarness>(
                &mut bench_group,
                handshake_type,
                ec_group,
            );
        }
    }
}

criterion_group!(benches, bench_handshake_params);
criterion_main!(benches);
