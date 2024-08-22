// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! These benchmarks compare the performance s2n_constant_time_equals with memcmp.
//! The benchmarks can be run with "cargo bench low-level-comparison"
//!
//! The results show that s2n_constant_time_equals is significantly slower than
//! memcmp, but that for small amounts of data the comparisons remain very cheap,
//! on the order of hundreds of nano-seconds.
//!
//! We also see that for pathological inputs, the overhead of the constant time
//! equals grows more noticeable, e.g. ~30 μs. This pathological case is roughly
//! modelled after what might be seen if a client totally fills an extension with
//! data. For this reason we generally avoid using s2n_constant_time_equals to
//! compare large amounts of data.

use criterion::{criterion_group, criterion_main, Criterion};
use rand::RngCore;
// we don't need any symbols from s2n-tls, but we do need to link against it to
// make s2n_constant_time_equals available.
use s2n_tls as _;
use std::ffi::c_void;

const SMALL_DATA_LENGTH: usize = u8::MAX as usize;
const MAX_EXTENSION_SIZE: usize = u16::MAX as usize;

// wrapper around the libc memcmp
fn memcmp(a: &[u8], b: &[u8]) -> i32 {
    unsafe {
        libc::memcmp(
            a.as_ptr() as *const c_void,
            b.as_ptr() as *const c_void,
            a.len(),
        )
    }
}

extern "C" {
    // s2n_constant_time_equals is not exposed publicly, so we manually write the
    // bindings for it.
    //
    // bool s2n_constant_time_equals(const uint8_t *a, const uint8_t *b, const uint32_t len)
    fn s2n_constant_time_equals(a: *const u8, b: *const u8, len: u32) -> bool;
}

fn rust_s2n_constant_time_equals(a: &[u8], b: &[u8]) -> bool {
    unsafe { s2n_constant_time_equals(a.as_ptr(), b.as_ptr(), a.len() as u32) }
}

fn comparison(criterion: &mut Criterion) {
    let mut a = [0; SMALL_DATA_LENGTH];
    let mut b = [0; SMALL_DATA_LENGTH];
    let mut a_copy = [0; SMALL_DATA_LENGTH];

    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut a);
    rng.fill_bytes(&mut b);

    // use a separate copy to avoid the timing difference caused by loads
    a_copy.copy_from_slice(&a);

    // compare memcmp vs s2n_constant_time_equals, small data && data equal
    let mut group = criterion.benchmark_group("low-level-comparison - small data, not equal");
    group.bench_function("memcmp", |bencher| bencher.iter(|| memcmp(&a, &b)));

    group.bench_function("s2n_constant_time_equals", |bencher| {
        bencher.iter(|| rust_s2n_constant_time_equals(&a, &b))
    });
    group.finish();

    // compare memcmp vs s2n_constant_time_equals, small data && data is not equal
    let mut group = criterion.benchmark_group("low-level-comparison - small data, equal");
    group.bench_function("memcmp", |bencher| bencher.iter(|| memcmp(&a, &a_copy)));
    group.bench_function("s2n_constant_time_equals_c", |bencher| {
        bencher.iter(|| rust_s2n_constant_time_equals(&a, &a_copy))
    });
    group.finish();

    let mut pathological_data = [[0; SMALL_DATA_LENGTH]; MAX_EXTENSION_SIZE / SMALL_DATA_LENGTH];
    for chunk in pathological_data.iter_mut() {
        rng.fill_bytes(chunk);
    }

    // compare memcmp vs s2n_constant_time_equals, lots of small data && data is not equal
    let mut group = criterion.benchmark_group("low-level-comparison - many small blobs, not equal");
    group.bench_function("memcmp", |bencher| {
        bencher.iter(|| {
            for e in pathological_data.iter() {
                std::hint::black_box(memcmp(e, &a));
            }
        })
    });

    group.bench_function("s2n_constant_time_equals", |bencher| {
        bencher.iter(|| {
            for e in pathological_data.iter() {
                rust_s2n_constant_time_equals(e, &a);
            }
        })
    });
    group.finish();
}

criterion_group!(benches, comparison);
criterion_main!(benches);
