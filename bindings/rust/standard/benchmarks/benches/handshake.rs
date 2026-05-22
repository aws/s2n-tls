// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use benchmarks::*;
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, Criterion,
};
use strum::IntoEnumIterator;
use tls_harness::{
    cohort::{OpenSslConnection, RustlsConnection, S2NConnection},
    harness::TlsInfo,
    Mode, SigType, TlsConnPair, TlsConnection,
};

fn bench_handshake_for_library<T>(
    bench_group: &mut BenchmarkGroup<WallTime>,
    handshake_type: HandshakeType,
    kx_group: KXGroup,
    sig_type: SigType,
) where
    T: TlsConnection + TlsInfo,
    T::Config: TlsBenchConfig,
{
    let crypto_config = CryptoConfig::new(CipherSuite::default(), kx_group, sig_type);
    let client_config =
        &T::Config::make_config(Mode::Client, crypto_config, handshake_type).unwrap();
    let server_config =
        &T::Config::make_config(Mode::Server, crypto_config, handshake_type).unwrap();

    // generate all harnesses (TlsConnPair structs) beforehand so that benchmarks
    // only include negotiation and not config/connection initialization
    bench_group.bench_function(T::name(), |b| {
        b.iter_batched_ref(
            || -> TlsConnPair<T, T> {
                if handshake_type == HandshakeType::Resumption {
                    // generate a session ticket to store on the config
                    let mut pair = TlsConnPair::<T, T>::from_configs(client_config, server_config);
                    pair.handshake().unwrap();
                    pair.round_trip_transfer(&mut [0]).unwrap();
                    pair.shutdown().unwrap();
                }
                TlsConnPair::from_configs(client_config, server_config)
            },
            |conn_pair| {
                conn_pair.handshake().unwrap();
                match handshake_type {
                    HandshakeType::ServerAuth | HandshakeType::MutualAuth => {
                        assert!(!conn_pair.server.resumed_connection())
                    }
                    HandshakeType::Resumption => assert!(conn_pair.server.resumed_connection()),
                }
            },
            // Use "PerIteration" benchmarking, because of the way that session
            // ticket setup interacts with shared configs.
            // > In testing, the maximum measurement overhead from benchmarking
            // > with PerIteration is on the order of 350 nanoseconds
            BatchSize::PerIteration,
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
    bench_handshake_for_library::<RustlsConnection>(
        bench_group,
        handshake_type,
        kx_group,
        sig_type,
    );
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

criterion_group! {
    benches, bench_handshake_types, bench_handshake_kx_groups, bench_handshake_sig_types
}
criterion_main!(benches);
