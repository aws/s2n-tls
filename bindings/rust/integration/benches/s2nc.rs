// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};
use std::{
    dbg, env,
    io::{self, Write},
    process::Command,
    time::Duration,
};
mod utils;

pub fn s2nc(c: &mut Criterion) {
    let mut group = c.benchmark_group("s2nc");
    let s2nc_env: &str = &env::var("S2NC_ARGS").unwrap();
    let s2nc_args: utils::Arguments = s2nc_env.into();
    let test_name = format!("s2nc{:?}", s2nc_args.get_endpoint().unwrap());

    group.bench_function(test_name, move |b| {
        b.iter(|| {
            let s2nc_env: &str = &env::var("S2NC_ARGS").unwrap();
            let s2nc_args: utils::Arguments = s2nc_env.into();
            dbg!("s2nc harness: {:?}", &s2nc_args);
            let output = Command::new("/usr/local/bin/s2nc")
                .args(s2nc_args.get_vec())
                .output()
                .expect("failed to execute process");

            io::stdout().write_all(&output.stdout).unwrap();
            io::stderr().write_all(&output.stderr).unwrap();
            dbg!("DEBUG: return code {:?}", &output.status);
        });
    });

    group.finish();
}

criterion_group!(name = benches;
                 config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(1));
                 targets = s2nc);
criterion_main!(benches);
