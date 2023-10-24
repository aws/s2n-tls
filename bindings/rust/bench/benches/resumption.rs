use bench::{
    harness::TlsBenchConfig, CipherSuite, CryptoConfig, HandshakeType, KXGroup, S2NConnection,
    SigType, TlsConnPair, TlsConnection,
};
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, Criterion,
};

fn bench_handshake_pair<T>(bench_group: &mut BenchmarkGroup<WallTime>, sig_type: SigType)
where
    T: TlsConnection,
    T::Config: TlsBenchConfig,
{
    // generate all harnesses (TlsConnPair structs) beforehand so that benchmarks
    // only include negotiation and not config/connection initialization
    for handshake in [HandshakeType::Resumption, HandshakeType::ServerAuth] {
        bench_group.bench_function(format!("{:?}-{}", handshake, T::name()), |b| {
            b.iter_batched_ref(
                || {
                    TlsConnPair::<T, T>::new_bench_pair(
                        CryptoConfig::new(CipherSuite::default(), KXGroup::default(), sig_type),
                        handshake,
                    )
                },
                |conn_pair_res| {
                    if let Ok(conn_pair) = conn_pair_res {
                        let _ = conn_pair.handshake();
                    }
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn bench_handshake_server_1rtt<T>(bench_group: &mut BenchmarkGroup<WallTime>, sig_type: SigType)
where
    T: TlsConnection,
    T::Config: TlsBenchConfig,
{
    for handshake in [HandshakeType::Resumption, HandshakeType::ServerAuth] {
        bench_group.bench_function(format!("{:?}-{}", handshake, T::name()), |b| {
            b.iter_batched_ref(
                || {
                    let pair = TlsConnPair::<T, T>::new_bench_pair(
                        CryptoConfig::new(CipherSuite::default(), KXGroup::default(), sig_type),
                        handshake,
                    )
                    .unwrap();
                    let (mut c, s) = pair.split();
                    c.handshake().unwrap();
                    s
                },
                |server| {
                    // this represents the work that the server does during the
                    // first RTT
                    server.handshake().unwrap()
                },
                BatchSize::SmallInput,
            )
        });
    }
}

/// This benchmark compares resumption savings across a single implementation.
/// E.g. "how much faster is session resumption than a full handshake for
/// s2n-tls?".
pub fn bench_resumption(c: &mut Criterion) {
    // compare resumption savings across both client and server
    for sig_type in [SigType::Rsa2048, SigType::Ecdsa384] {
        let mut bench_group = c.benchmark_group(format!("resumption-pair-{:?}", sig_type));
        bench_handshake_pair::<S2NConnection>(&mut bench_group, sig_type);
    }

    // only look at resumption savings for the server, specifically the work
    // done in the first rtt.
    for sig_type in [SigType::Rsa2048, SigType::Ecdsa384] {
        let mut bench_group = c.benchmark_group(format!("resumption-server-1rtt-{:?}", sig_type));
        bench_handshake_server_1rtt::<S2NConnection>(&mut bench_group, sig_type);
    }
}

criterion_group!(benches, bench_resumption);
criterion_main!(benches);
