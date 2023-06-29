// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use criterion::{
    criterion_group, criterion_main,
    measurement::{Measurement, ValueFormatter},
    BenchmarkGroup, Criterion,
};
use rand::thread_rng;
use rand_distr::{Distribution, Normal};
use std::{fs::read_to_string, path::Path, time::Duration};

fn get_bytes_from_snapshot(name: &str, i: i32) -> i32 {
    // number of bytes in snapshot starts on 8th line, 12th character
    read_to_string(format!("target/memory/{name}/{i}.snapshot"))
        .unwrap()
        .lines()
        .nth(7)
        .unwrap()[11..]
        .parse()
        .unwrap()
}

/// Get the difference in bytes between two snapshots, which is memory of the
/// `i`th TlsBenchHarness (client and server)
fn get_bytes_diff(name: &str, i: i32) -> i32 {
    get_bytes_from_snapshot(name, i + 1) - get_bytes_from_snapshot(name, i)
}

/// Read in memory snapshots and give Criterion memory values to analyze and plot
fn read_library(group: &mut BenchmarkGroup<'_, Bytes>, name: &str) {
    if !Path::new("target/memory/").is_dir() {
        panic!("need to run memory-bench.sh first");
    }

    let mut i = 0;
    let normal = Normal::new(0.0, 10000.0).unwrap();
    group.bench_function(name, |b| {
        // iter_custom requires closure returning time taken for `iters` iterations
        // read in `iters` memory snapshots and return sum of memory taken
        b.iter_custom(|iters| {
            let mut sum = 0;
            for _ in 0..iters {
                sum += get_bytes_diff(name, i) + normal.sample(&mut thread_rng()) as i32; // add jitter for plotting
                i = (i + 1) % 100; // read in snapshots again if ran out
            }
            sum / 2 // TlsBenchHarness has two conns, half to get memory of one conn
        })
    });
}

/// This function only reads the output files from memory/valgrind.sh and doesn't
/// run benchmarks itself. Running a Valgrind benchmark in Rust/Criterion takes
/// much longer (10x) than running it in a separate shell script.
pub fn read_memory_bench(c: &mut Criterion<Bytes>) {
    let mut group = c.benchmark_group("memory");
    group.sample_size(100);
    group.warm_up_time(Duration::from_nanos(1)); // no warm up because not timing anything

    for name in ["s2n-tls", "rustls", "openssl"] {
        read_library(&mut group, name);
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_measurement(Bytes);
    targets = read_memory_bench
}
criterion_main!(benches);

/// Used for custom units for memory benchmark
pub struct Bytes;
impl Measurement for Bytes {
    type Intermediate = i32;
    type Value = i32;

    fn start(&self) -> Self::Intermediate {
        0
    }

    fn end(&self, _: Self::Intermediate) -> Self::Value {
        0
    }

    fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
        v1 + v2
    }

    fn zero(&self) -> Self::Value {
        0
    }

    fn to_f64(&self, value: &Self::Value) -> f64 {
        *value as _
    }

    fn formatter(&self) -> &dyn ValueFormatter {
        &BytesFormatter
    }
}

/// Used for custom units for memory benchmark
struct BytesFormatter;
impl ValueFormatter for BytesFormatter {
    fn scale_values(&self, _: f64, values: &mut [f64]) -> &'static str {
        for val in values {
            *val /= 1024.;
        }
        "KB"
    }
    fn scale_throughputs(&self, _: f64, _: &criterion::Throughput, _: &mut [f64]) -> &'static str {
        ""
    }
    fn scale_for_machines(&self, _: &mut [f64]) -> &'static str {
        ""
    }
}
