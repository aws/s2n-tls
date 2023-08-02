// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "openssl")]
use bench::OpenSslConnection;
#[cfg(feature = "rustls")]
use bench::RustlsConnection;
use bench::{
    harness::ConnectedBuffer, CipherSuite, CryptoConfig, HandshakeType, KXGroup, Mode,
    S2NConnection, SigType, TlsConnPair, TlsConnection,
};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, Criterion,
};
use pprof::criterion::{Output, PProfProfiler};
use std::error::Error;
use strum::IntoEnumIterator;

fn bench_handshake_for_library<T: TlsConnection>(
    bench_group: &mut BenchmarkGroup<WallTime>,
    handshake_type: HandshakeType,
    kx_group: KXGroup,
    sig_type: SigType,
) {
    // make configs before benching to reuse
    let crypto_config = CryptoConfig::new(CipherSuite::default(), kx_group, sig_type);
    let client_config = T::make_config(Mode::Client, crypto_config, handshake_type);
    let server_config = T::make_config(Mode::Server, crypto_config, handshake_type);

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
                        T::new_from_config(&client_config, connected_buffer.clone_inverse())?;
                    let server = T::new_from_config(&server_config, connected_buffer)?;
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
                #[cfg(feature = "rustls")]
                bench_handshake_for_library::<RustlsConnection>(
                    &mut bench_group,
                    handshake_type,
                    kx_group,
                    sig_type,
                );
                #[cfg(feature = "openssl")]
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

criterion_group! {
    name = benches;
    // profile 100 samples/sec
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench_handshake_params
}
criterion_main!(benches);
