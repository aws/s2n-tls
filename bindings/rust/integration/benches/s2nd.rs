// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};
use std::{env, process::Command};
mod utils;

pub fn s2nd(c: &mut Criterion) {
    let mut group = c.benchmark_group("s2nd");
    let s2nd_env: &str = &env::var("S2ND_ARGS").unwrap();
    let s2nd_args: utils::Arguments = s2nd_env.into();
    let test_name = format!("s2nd_{}", s2nd_args.get_endpoint().unwrap());
    dbg!("Parsed test_name as: {:?}", &test_name);
    let s2nd_env: &str = &env::var("S2ND_ARGS").unwrap();
    let s2nd_args: utils::Arguments = s2nd_env.into();
    dbg!("s2nd harness: {:?}", &s2nd_args);
    group.bench_function(test_name, move |b| {
        b.iter(|| {
            let s2nd_argvec = s2nd_args.clone().get_vec();
            let status = Command::new("/usr/local/bin/s2nd")
                .args(s2nd_argvec)
                .status()
                .expect("failed to execute process");
            assert!(status.success());
        });
    });

    group.finish();
}

criterion_group!(benches, s2nd);
criterion_main!(benches);
