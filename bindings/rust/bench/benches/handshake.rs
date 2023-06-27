// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{RustlsHarness, S2NHarness, TlsBenchHarness};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

pub fn bench_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");

    macro_rules! bench_handshake_for_libraries {
        ($(($lib_name:expr, $lib_type:ty),)*) => {
        $(
            // generate all inputs (TlsBenchHarness structs) before benchmarking handshakes
            // timing only includes negotiation, not config/connection initialization
            group.bench_function($lib_name, |b| {
                b.iter_batched_ref(
                    || <$lib_type>::default().unwrap(),
                    |harness| {
                        harness.handshake().unwrap();
                    },
                    BatchSize::SmallInput,
                )
            });
        )*
        }
    }

    bench_handshake_for_libraries! {
        ("s2n-tls", S2NHarness),
        ("rustls", RustlsHarness),
    }

    group.finish();
}

criterion_group!(benches, bench_handshake);
criterion_main!(benches);
