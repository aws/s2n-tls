// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use benchmarks::*;
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, Criterion,
    Throughput,
};
use strum::IntoEnumIterator;
use tls_harness::{
    cohort::{OpenSslConnection, RustlsConnection, S2NConnection},
    harness::TlsInfo,
    Mode, SigType, TlsConnPair, TlsConnection,
};

fn bench_throughput_for_library<T>(
    bench_group: &mut BenchmarkGroup<WallTime>,
    shared_buf: &mut [u8],
    cipher_suite: CipherSuite,
) where
    T: TlsConnection + TlsInfo,
    T::Config: TlsBenchConfig,
{
    let crypto_config = CryptoConfig::new(cipher_suite, KXGroup::default(), SigType::default());
    let client_config =
        T::Config::make_config(Mode::Client, crypto_config, HandshakeType::default()).unwrap();
    let server_config =
        T::Config::make_config(Mode::Server, crypto_config, HandshakeType::default()).unwrap();

    bench_group.bench_function(T::name(), |b| {
        b.iter_batched_ref(
            || -> TlsConnPair<T, T> {
                let mut conn_pair = TlsConnPair::from_configs(&client_config, &server_config);
                conn_pair.handshake().unwrap();
                conn_pair
            },
            |conn_pair| {
                let _ = conn_pair.round_trip_transfer(shared_buf);
            },
            BatchSize::SmallInput,
        )
    });
}

pub fn bench_throughput_cipher_suites(c: &mut Criterion) {
    // arbitrarily large to cut across TLS record boundaries
    let mut shared_buf = [0u8; 100000];

    for cipher_suite in CipherSuite::iter() {
        let mut bench_group = c.benchmark_group(format!("throughput-{cipher_suite:?}"));
        bench_group.throughput(Throughput::Bytes(shared_buf.len() as u64));
        bench_throughput_for_library::<S2NConnection>(
            &mut bench_group,
            &mut shared_buf,
            cipher_suite,
        );
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

criterion_group! {benches, bench_throughput_cipher_suites}
criterion_main!(benches);
