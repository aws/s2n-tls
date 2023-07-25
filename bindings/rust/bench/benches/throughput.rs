// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{
    CipherSuite::{self, *},
    CryptoConfig, ECGroup, HandshakeType, OpenSslHarness, RustlsHarness, S2NHarness, SigType,
    TlsBenchHarness, harness::ConnectedBuffer,
};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, Criterion,
    Throughput,
};

pub fn bench_throughput_cipher_suite(c: &mut Criterion) {
    // arbitrarily large to cut across TLS record boundaries
    let mut shared_buf = [0u8; 100000];

    fn bench_throughput_for_library<T: TlsBenchHarness>(
        bench_group: &mut BenchmarkGroup<WallTime>,
        name: &str,
        shared_buf: &mut [u8],
        cipher_suite: CipherSuite,
    ) {
        bench_group.bench_function(name, |b| {
            b.iter_batched_ref(
                || {
                    T::new(
                        CryptoConfig::new(cipher_suite, ECGroup::default(), SigType::default()),
                        HandshakeType::default(),
                        ConnectedBuffer::default(),
                    )
                    .map(|mut h| {
                        let _ = h.handshake();
                        h
                    })
                },
                |harness| {
                    if let Ok(harness) = harness {
                        let _ = harness.round_trip_transfer(shared_buf);
                    }
                },
                BatchSize::SmallInput,
            )
        });
    }

    for cipher_suite in [AES_128_GCM_SHA256, AES_256_GCM_SHA384] {
        let mut bench_group = c.benchmark_group(format!("throughput-{:?}", cipher_suite));
        bench_group.throughput(Throughput::Bytes(shared_buf.len() as u64));
        bench_throughput_for_library::<S2NHarness>(
            &mut bench_group,
            "s2n-tls",
            &mut shared_buf,
            cipher_suite,
        );
        #[cfg(not(feature = "historical-perf"))]
        {
            bench_throughput_for_library::<RustlsHarness>(
                &mut bench_group,
                "rustls",
                &mut shared_buf,
                cipher_suite,
            );
            bench_throughput_for_library::<OpenSslHarness>(
                &mut bench_group,
                "openssl",
                &mut shared_buf,
                cipher_suite,
            );
        }
    }
}

criterion_group!(benches, bench_throughput_cipher_suite);
criterion_main!(benches);
