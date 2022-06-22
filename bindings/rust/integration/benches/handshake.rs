// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};
use s2n_tls::{
    security,
    testing::{build_config, s2n_tls_pair},
};

pub fn handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("s2n-tls_client_server");

    for policy in security::ALL_POLICIES {
        let config = build_config(policy).unwrap();
        group.bench_function(format!("handshake_{:?}", policy), move |b| {
            // This does include connection initalization overhead.
            // TODO: create a separate benchamrk that excludes this step.
            b.iter(|| s2n_tls_pair(config.clone()));
        });
    }

    group.finish();
}

criterion_group!(benches, handshake);
criterion_main!(benches);
