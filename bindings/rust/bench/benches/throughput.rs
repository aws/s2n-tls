// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{
    CipherSuite::{self, *},
    CryptoConfig, OpenSslHarness, RustlsHarness, S2NHarness, TlsBenchHarness,
};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, Criterion,
    Throughput,
};
use std::any::type_name;

pub fn bench_throughput_cipher_suite(c: &mut Criterion) {
    // arbitrarily large to cut across TLS record boundaries
    let mut shared_buf = [0u8; 100000];

    fn bench_throughput_for_library<T: TlsBenchHarness>(
        bench_group: &mut BenchmarkGroup<WallTime>,
        shared_buf: &mut [u8],
        cipher_suite: CipherSuite,
    ) {
        bench_group.bench_function(type_name::<T>(), |b| {
            b.iter_batched_ref(
                || {
                    let mut harness = T::new(
                        CryptoConfig {
                            cipher_suite,
                            ec_group: Default::default(),
                        },
                        Default::default(),
                    )
                    .unwrap();
                    harness.handshake().unwrap();
                    harness
                },
                |harness| harness.round_trip_transfer(shared_buf).unwrap(),
                BatchSize::SmallInput,
            )
        });
    }

    for cipher_suite in [AES_128_GCM_SHA256, AES_256_GCM_SHA384] {
        let mut bench_group = c.benchmark_group(format!("throughput-{:?}", cipher_suite));
        bench_group.throughput(Throughput::Bytes(shared_buf.len() as u64));
        bench_throughput_for_library::<S2NHarness>(&mut bench_group, &mut shared_buf, cipher_suite);
        bench_throughput_for_library::<RustlsHarness>(
            &mut bench_group,
            &mut shared_buf,
            cipher_suite,
        );
        bench_throughput_for_library::<OpenSslHarness>(
            &mut bench_group,
            &mut shared_buf,
            cipher_suite,
        );
    }
}

criterion_group!(benches, bench_throughput_cipher_suite);
criterion_main!(benches);
