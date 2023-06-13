// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{S2nTls, TlsBenchHarness};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");

    group.bench_function("s2n-tls", |b| {
        b.iter_batched_ref(
            || S2nTls::new(),
            |s2n_tls| {
                s2n_tls.handshake();
            },
            BatchSize::SmallInput, // pregenerates batch of inputs to pass to function being benchmarked
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
