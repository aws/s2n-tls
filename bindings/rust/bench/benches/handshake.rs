use bench::{OpenSsl, Rustls, S2nTls, TlsImpl};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");

    // SmallInput: inputs of `TlsImpl::new()` are sufficiently small to pregenerate and store in memory

    group.bench_function("rustls", |b| {
        b.iter_batched_ref(
            || Rustls::new(),
            |rustls| {
                rustls.handshake();
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("openssl", |b| {
        b.iter_batched_ref(
            || OpenSsl::new(),
            |openssl| {
                openssl.handshake();
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("s2n-tls", |b| {
        b.iter_batched_ref(
            || S2nTls::new(),
            |s2n_tls| {
                s2n_tls.handshake();
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
