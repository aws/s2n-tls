// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};
use subprocess::Exec;
use std::env;

pub fn s2nc(c: &mut Criterion) {
    let mut group = c.benchmark_group("s2nc");
    let s2nc_args = env!("S2NC_ARGS");
    // Env vars needed, so far: .cargo/bin, s2n-tls/bin, 
    // export S2NC_ARGS="-t 2 -f /opt/s2n/tests/integration/trust-store/ca-bundle.crt -a http/1.1 -C www.amazon.com"
    let path = env::current_dir(); println!("path: {:?}", path);
        group.bench_function(format!("s2n_client"), move |b| {
            // This does include connection initalization overhead.
            b.iter(|| Exec::cmd("s2nc").arg(s2nc_args));
            println!("running s2nc with args {:?}",s2nc_args);
            // ./bin/s2nc -t 2  -f ../tests/integration/trust-store/ca-bundle.crt  -a http/1.1 -C www.amazon.com
        });

    group.finish();
}

criterion_group!(benches, s2nc);
criterion_main!(benches);
