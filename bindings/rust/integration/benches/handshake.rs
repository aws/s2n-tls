// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};
use subprocess::Exec;

pub fn handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("s2n-tls_client_server");

        group.bench_function(format!("handshake_"), move |b| {
            // This does include connection initalization overhead.
            // TODO: create a separate benchamrk that excludes this step.
            b.iter(|| Exec::shell("pstree").join());
        });

    group.finish();
}

criterion_group!(benches, handshake);
criterion_main!(benches);
