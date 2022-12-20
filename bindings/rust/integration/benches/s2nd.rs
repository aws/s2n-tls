// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};
use std::{env, process::Command, time::Duration};

pub fn s2nd(c: &mut Criterion) {
    let mut group = c.benchmark_group("s2nd");
    let s2nd_env: &str = &env::var("S2ND_ARGS").unwrap();
    let s2nd_test_name: &str = &env::var("S2ND_TEST_NAME").unwrap();
    let test_name = format!("s2nd_{}", s2nd_test_name);
    let s2nd_split = s2nd_env.split(' ').collect::<Vec<&str>>();
    group.bench_function(test_name, move |b| {
        b.iter(|| {
            let s2nd_argvec = s2nd_split.clone();
            let status = Command::new("/usr/local/bin/s2nd")
                .args(s2nd_argvec)
                .status()
                .expect("failed to execute process");
            assert!(status.success());
        });
    });

    group.finish();
}

criterion_group!(name = benches;
                 config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(1));
                 targets = s2nd);
criterion_main!(benches);
