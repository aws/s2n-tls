// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};
use std::{env, fs};
use subprocess::{Exec, Redirection};

pub fn s2nd(c: &mut Criterion) {
    let mut group = c.benchmark_group("s2n_daemon");
    let s2nc_args = env!("S2ND_ARGS");
    group.bench_function(format!("s2nd"), move |b| {
        b.iter(|| {
        let output = fs::File::create("s2nd_criterion.out").unwrap();
            // Write out to a file so the tests can check output.
            Exec::cmd("s2nd")
                .arg(s2nc_args)
                .stdout(Redirection::File(output))
                .stderr(Redirection::Merge)
                .capture()
        });
    });

    group.finish();
}

criterion_group!(benches, s2nd);
criterion_main!(benches);
