// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{
    harness::ConnectedBuffer, CipherSuite, CryptoConfig, HandshakeType, KXGroup, OpenSslConnection,
    RustlsConnection, S2NConnection, SigType, TlsConnPair, TlsConnection,
};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, Criterion,
    Throughput,
};
use strum::IntoEnumIterator;

pub fn bench_throughput_cipher_suite(c: &mut Criterion) {
    // arbitrarily large to cut across TLS record boundaries
    let mut shared_buf = [0u8; 100000];

    fn bench_throughput_for_library<T: TlsConnection>(
        bench_group: &mut BenchmarkGroup<WallTime>,
        shared_buf: &mut [u8],
        cipher_suite: CipherSuite,
    ) {
        bench_group.bench_function(T::name(), |b| {
            b.iter_batched_ref(
                || {
                    TlsConnPair::<T, T>::new(
                        CryptoConfig::new(cipher_suite, KXGroup::default(), SigType::default()),
                        HandshakeType::default(),
                        ConnectedBuffer::default(),
                    )
                    .map(|mut h| {
                        let _ = h.handshake();
                        h
                    })
                },
                |conn_pair_res| {
                    if let Ok(conn_pair) = conn_pair_res {
                        let _ = conn_pair.round_trip_transfer(shared_buf);
                    }
                },
                BatchSize::SmallInput,
            )
        });
    }

    for cipher_suite in CipherSuite::iter() {
        let mut bench_group = c.benchmark_group(format!("throughput-{:?}", cipher_suite));
        bench_group.throughput(Throughput::Bytes(shared_buf.len() as u64));
        bench_throughput_for_library::<S2NConnection>(
            &mut bench_group,
            &mut shared_buf,
            cipher_suite,
        );
        #[cfg(not(feature = "historical-perf"))]
        {
            bench_throughput_for_library::<RustlsConnection>(
                &mut bench_group,
                &mut shared_buf,
                cipher_suite,
            );
            bench_throughput_for_library::<OpenSslConnection>(
                &mut bench_group,
                &mut shared_buf,
                cipher_suite,
            );
        }
    }
}

criterion_group!(benches, bench_throughput_cipher_suite);
criterion_main!(benches);
