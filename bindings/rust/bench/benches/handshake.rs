// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "openssl")]
use bench::OpenSslConnection;
#[cfg(feature = "rustls")]
use bench::RustlsConnection;
use bench::{
    CipherSuite, CryptoConfig, HandshakeType, KXGroup, S2NConnection, SigType, TlsConnPair,
    TlsConnection,
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
                    Default::default(),
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

fn bench_handshake_with_params(
    bench_group: &mut BenchmarkGroup<WallTime>,
    handshake_type: HandshakeType,
    kx_group: KXGroup,
    sig_type: SigType,
) {
    bench_handshake_for_library::<S2NConnection>(bench_group, handshake_type, kx_group, sig_type);
    #[cfg(feature = "rustls")]
    bench_handshake_for_library::<RustlsConnection>(
        bench_group,
        handshake_type,
        kx_group,
        sig_type,
    );
    #[cfg(feature = "openssl")]
    bench_handshake_for_library::<OpenSslConnection>(
        bench_group,
        handshake_type,
        kx_group,
        sig_type,
    );
}

pub fn bench_handshake_types(c: &mut Criterion) {
    for handshake_type in HandshakeType::iter() {
        let mut bench_group = c.benchmark_group(format!("handshake-{handshake_type:?}"));
        bench_handshake_with_params(
            &mut bench_group,
            handshake_type,
            KXGroup::default(),
            SigType::default(),
        );
    }
}

pub fn bench_handshake_kx_groups(c: &mut Criterion) {
    for kx_group in KXGroup::iter() {
        let mut bench_group = c.benchmark_group(format!("handshake-{kx_group:?}"));
        bench_handshake_with_params(
            &mut bench_group,
            HandshakeType::default(),
            kx_group,
            SigType::default(),
        );
    }
}

pub fn bench_handshake_sig_types(c: &mut Criterion) {
    for sig_type in SigType::iter() {
        let mut bench_group = c.benchmark_group(format!("handshake-{sig_type:?}"));
        bench_handshake_with_params(
            &mut bench_group,
            HandshakeType::default(),
            KXGroup::default(),
            sig_type,
        );
    }
}

criterion_group!(
    benches,
    bench_handshake_types,
    bench_handshake_kx_groups,
    bench_handshake_sig_types
);
criterion_main!(benches);
