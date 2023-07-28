// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{
    CipherSuite, CryptoConfig, HandshakeType, KXGroup, OpenSslConnection, RustlsConnection,
    S2NConnection, SigType, TlsConnPair, TlsConnection, ConnectedBuffer,
};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, Criterion,
};
use strum::IntoEnumIterator;

fn bench_handshake_for_library<T: TlsConnection>(
    bench_group: &mut BenchmarkGroup<WallTime>,
    handshake_type: HandshakeType,
    kx_group: KXGroup,
    sig_type: SigType,
) {
    // generate all harnesses (TlsConnPair structs) beforehand so that benchmarks
    // only include negotiation and not config/connection initialization
    bench_group.bench_function(T::name(), |b| {
        b.iter_batched_ref(
            || {
                TlsConnPair::<T, T>::new(
                    CryptoConfig::new(CipherSuite::default(), kx_group, sig_type),
                    handshake_type,
                    ConnectedBuffer::default(),
                )
            },
            |conn_pair_res| {
                // harnesses with certain parameters fail to initialize for
                // some past versions of s2n-tls, but missing data can be
                // visually interpolated in the historical performance graph
                if let Ok(conn_pair) = conn_pair_res {
                    let _ = conn_pair.handshake();
                }
            },
            BatchSize::SmallInput,
        )
    });
}

pub fn bench_handshake_params(c: &mut Criterion) {
    for handshake_type in HandshakeType::iter() {
        for kx_group in KXGroup::iter() {
            for sig_type in SigType::iter() {
                let mut bench_group = c.benchmark_group(match handshake_type {
                    HandshakeType::ServerAuth => format!("handshake-{:?}-{:?}", kx_group, sig_type),
                    HandshakeType::MutualAuth => {
                        format!("handshake-mTLS-{:?}-{:?}", kx_group, sig_type)
                    }
                });
                bench_handshake_for_library::<S2NConnection>(
                    &mut bench_group,
                    handshake_type,
                    kx_group,
                    sig_type,
                );
                #[cfg(not(feature = "historical-perf"))]
                {
                    bench_handshake_for_library::<RustlsConnection>(
                        &mut bench_group,
                        handshake_type,
                        kx_group,
                        sig_type,
                    );
                    bench_handshake_for_library::<OpenSslConnection>(
                        &mut bench_group,
                        handshake_type,
                        kx_group,
                        sig_type,
                    );
                }
            }
        }
    }
}

criterion_group!(benches, bench_handshake_params);
criterion_main!(benches);
