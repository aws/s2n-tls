// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::testing::s2n_tls::tests::{build_config, s2n_tls_pair};
use s2n_tls::raw::securitypolicy::*;
use criterion::{criterion_group, criterion_main, Criterion};

pub fn handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("s2n-tls (client) - s2n-tls (server)");

    let config = build_config(DEFAULT).unwrap();
    group.bench_function("handshake_default", |b| {
        b.iter(|| s2n_tls_pair(config.clone()))
    });
    let config = build_config(DEFAULT_TLS13).unwrap();
    group.bench_function("handshake_default_tls13", |b| {
        b.iter(|| s2n_tls_pair(config.clone()))
    });
    group.finish();
}

criterion_group!(benches, handshake);
criterion_main!(benches);
