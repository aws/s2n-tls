// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};
use s2n_tls::{
    config::Config,
    connection::Builder,
    enums::Mode,
    pool::{ConfigPool, ConfigPoolBuilder, PooledConnection},
};
use std::sync::Arc;

fn connection_wipe(connection_pool: &Arc<ConfigPool>) {
    // get a connection from the pool
    let conn = PooledConnection::new(connection_pool).unwrap();
    // "drop" the connection, wiping it and returning it to the pool
    drop(conn);
}

fn connection_new(config: &Config) {
    let conn = config
        .build_connection(s2n_tls::enums::Mode::Server)
        .unwrap();
    drop(conn);
}

fn connection_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Connection Creation");
    let config = s2n_tls::config::Builder::new().build().unwrap();
    let connection_pool = ConfigPoolBuilder::new(Mode::Server, config.clone()).build();

    group.bench_function("connection reuse", |b| {
        b.iter(|| connection_wipe(&connection_pool));
    });

    group.bench_function("connection allocation", |b| {
        b.iter(|| connection_new(&config));
    });

    group.finish();
}

criterion_group!(benches, connection_creation);
criterion_main!(benches);
