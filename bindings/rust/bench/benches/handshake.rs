// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{S2NHarness, TlsBenchHarness};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");

    group.bench_function("s2n-tls", |b| {
        // generate all inputs (s2n-tls objects) before benchmarking handshakes
        b.iter_batched_ref(
            || S2NHarness::new(),
            |s2n_tls| {
                s2n_tls.handshake().unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
