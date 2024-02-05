// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "openssl")]
use bench::OpenSslConnection;
#[cfg(feature = "rustls")]
use bench::RustlsConnection;
use bench::{
    harness::TlsBenchConfig, CipherSuite, ConnectedBuffer, CryptoConfig, HandshakeType, KXGroup,
    Mode, S2NConnection, SigType, TlsConnPair, TlsConnection, PROFILER_FREQUENCY,
};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, Criterion,
};
use pprof::criterion::{Output, PProfProfiler};
use std::error::Error;
use strum::IntoEnumIterator;

fn bench_handshake_for_library<T>(
    bench_group: &mut BenchmarkGroup<WallTime>,
    handshake_type: HandshakeType,
    kx_group: KXGroup,
    sig_type: SigType,
) where
    T: TlsConnection,
    T::Config: TlsBenchConfig,
{
    // make configs before benching to reuse
    let crypto_config = CryptoConfig::new(CipherSuite::default(), kx_group, sig_type);
    let client_config = T::Config::make_config(Mode::Client, crypto_config, handshake_type);
    let server_config = T::Config::make_config(Mode::Server, crypto_config, handshake_type);

    // generate all harnesses (TlsConnPair structs) beforehand so that benchmarks
    // only include negotiation and not config/connection initialization
    bench_group.bench_function(T::name(), |b| {
        b.iter_batched_ref(
            || -> Result<TlsConnPair<T, T>, Box<dyn Error>> {
                if let (Ok(client_config), Ok(server_config)) =
                    (client_config.as_ref(), server_config.as_ref())
                {
                    let connected_buffer = ConnectedBuffer::default();
                    let client =
                        T::new_from_config(client_config, connected_buffer.clone_inverse())?;
                    let server = T::new_from_config(server_config, connected_buffer)?;
                    Ok(TlsConnPair::wrap(client, server))
                } else {
                    Err("invalid configs".into())
                }
            },
            |conn_pair| {
                // harnesses with certain parameters fail to initialize for
                // some past versions of s2n-tls, but missing data can be
                // visually interpolated in the historical performance graph
                if let Ok(conn_pair) = conn_pair {
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

criterion_group! {
    name = benches;
    // profile 100 samples/sec
    config = Criterion::default().with_profiler(PProfProfiler::new(PROFILER_FREQUENCY, Output::Flamegraph(None)));
    targets = bench_handshake_types, bench_handshake_kx_groups, bench_handshake_sig_types
}
criterion_main!(benches);
