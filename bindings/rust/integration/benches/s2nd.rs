// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};
use std::{
    env,
    io::{self, Write},
    process::Command,
};

pub fn s2nd(c: &mut Criterion) {
    let mut group = c.benchmark_group("s2n_server");
    group.bench_function(
        format!("{:?}_s2nd", env::var("TOX_TEST_NAME").unwrap()),
        move |b| {
            b.iter(|| {
                let s2nd_args = env::var("S2ND_ARGS").unwrap();
                assert_ne!(s2nd_args.len(), 0);
                let output = Command::new("/usr/local/bin/s2nd")
                    .arg(s2nd_args)
                    .output()
                    .expect("failed to execute process");

                io::stdout().write_all(&output.stdout).unwrap();
                io::stderr().write_all(&output.stderr).unwrap();
            });
        },
    );

    group.finish();
}

criterion_group!(benches, s2nd);
criterion_main!(benches);
