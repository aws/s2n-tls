// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};
use std::{env, process::Command, time::Duration};

pub fn s2nc(c: &mut Criterion) {
    let mut group = c.benchmark_group("s2nc");
    /*
    example S2NC_ARGS:
    "--non-blocking -T -f ../integration/trust-store/ca-bundle.crt -c test_all_tls13 www.netflix.com 443"
    Set in tests/integrationv2/providers.py line 379-ish
    */
    let s2nc_env: &str = &env::var("S2NC_ARGS").unwrap();
    let s2nc_split = s2nc_env.split(' ').collect::<Vec<&str>>();
    let test_name = format!("s2nc_{}_{}", s2nc_split[5], s2nc_split[6]);
    group.bench_function(test_name, move |b| {
        b.iter(|| {
            let s2nc_argvec = s2nc_split.clone();
            let status = Command::new("/usr/local/bin/s2nc")
                .args(s2nc_argvec)
                .status()
                .expect("failed to execute process");
            assert!(status.success());
        });
    });

    group.finish();
}

criterion_group!(name = benches;
                 config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(1));
                 targets = s2nc);
criterion_main!(benches);
