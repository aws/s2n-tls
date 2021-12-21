// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};
use std::{
    dbg, env,
    io::{self, Write},
    process::Command,
};

pub fn s2nc(c: &mut Criterion) {
    let mut group = c.benchmark_group("s2nc");
    let test_name = format!("s2nc");
    group.bench_function(test_name, move |b| {
        b.iter(|| {
            let s2nc_args = env::var("S2NC_ARGS").unwrap();
            let s2nc_args_split = s2nc_args.split(' ');
            let s2nc_args_vec = s2nc_args_split.collect::<Vec<&str>>();
            dbg!("DEBUG: S2NC_ARGS {:?}", &s2nc_args_vec);
            assert_ne!(s2nc_args.len(), 0);
            let output = Command::new("/opt/s2n/bin/s2nc")
                .args(s2nc_args_vec)
                .output()
                .expect("failed to execute process");

            io::stdout().write_all(&output.stdout).unwrap();
            io::stderr().write_all(&output.stderr).unwrap();
            dbg!("DEBUG: return code {:?}", &output.status);
        });
    });

    group.finish();
}

criterion_group!(benches, s2nc);
criterion_main!(benches);
