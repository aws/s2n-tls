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
    Throughput,
};
use pprof::criterion::{Output, PProfProfiler};
use std::error::Error;
use strum::IntoEnumIterator;

fn bench_throughput_for_library<T>(
    bench_group: &mut BenchmarkGroup<WallTime>,
    shared_buf: &mut [u8],
    cipher_suite: CipherSuite,
) where
    T: TlsConnection,
    T::Config: TlsBenchConfig,
{
    let crypto_config = CryptoConfig::new(cipher_suite, KXGroup::default(), SigType::default());
    let client_config = T::Config::make_config(Mode::Client, crypto_config, HandshakeType::default());
    let server_config = T::Config::make_config(Mode::Server, crypto_config, HandshakeType::default());

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
                    let mut conn_pair = TlsConnPair::wrap(client, server);
                    conn_pair.handshake()?;
                    Ok(conn_pair)
                } else {
                    Err("invalid configs".into())
                }
            },
            |conn_pair| {
                if let Ok(conn_pair) = conn_pair {
                    let _ = conn_pair.round_trip_transfer(shared_buf);
                }
            },
            BatchSize::SmallInput,
        )
    });
}

pub fn bench_throughput_cipher_suites(c: &mut Criterion) {
    // arbitrarily large to cut across TLS record boundaries
    let mut shared_buf = [0u8; 100000];

    for cipher_suite in CipherSuite::iter() {
        let mut bench_group = c.benchmark_group(format!("throughput-{:?}", cipher_suite));
        bench_group.throughput(Throughput::Bytes(shared_buf.len() as u64));
        bench_throughput_for_library::<S2NConnection>(
            &mut bench_group,
            &mut shared_buf,
            cipher_suite,
        );
        #[cfg(feature = "rustls")]
        bench_throughput_for_library::<RustlsConnection>(
            &mut bench_group,
            &mut shared_buf,
            cipher_suite,
        );
        #[cfg(feature = "openssl")]
        bench_throughput_for_library::<OpenSslConnection>(
            &mut bench_group,
            &mut shared_buf,
            cipher_suite,
        );
    }
}

criterion_group! {
    name = benches;
    // profile 100 samples/sec
    config = Criterion::default().with_profiler(PProfProfiler::new(PROFILER_FREQUENCY, Output::Flamegraph(None)));
    targets = bench_throughput_cipher_suites
}
criterion_main!(benches);
