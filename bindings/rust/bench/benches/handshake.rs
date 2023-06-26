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
use std::any::type_name;

pub fn bench_handshake_key_exchange(c: &mut Criterion) {
    fn bench_handshake_for_library<T: TlsBenchHarness>(
        bench_group: &mut BenchmarkGroup<WallTime>,
        ec_group: &ECGroup,
    ) {
        bench_group.bench_function(type_name::<T>(), |b| {
            b.iter_batched_ref(
                || {
                    T::new(&CryptoConfig {
                        cipher_suite: AES_128_GCM_SHA256,
                        ec_group: *ec_group,
                    })
                    .unwrap()
                },
                |harness| {
                    harness.handshake().unwrap();
                },
                BatchSize::SmallInput,
            )
        });
    }

    for ec_group in [SECP256R1, X25519] {
        let mut bench_group = c.benchmark_group(format!("handshake-{:?}", ec_group));
        bench_handshake_for_library::<S2NHarness>(&mut bench_group, &ec_group);
        bench_handshake_for_library::<RustlsHarness>(&mut bench_group, &ec_group);
        bench_handshake_for_library::<OpenSslHarness>(&mut bench_group, &ec_group);
    }
}

criterion_group!(benches, bench_handshake_key_exchange);
criterion_main!(benches);
