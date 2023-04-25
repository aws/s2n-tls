// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, Criterion};
use s2n_tls::{security, testing::config_builder};
use std::{fs::File, io::Read, path::Path};

pub fn dh_params(c: &mut Criterion) {
    let mut group = c.benchmark_group("s2n-tls_dhparams");
    group.sample_size(10);

    // Generated using `openssl dhparam -out dhparams_4096.pem 4096`
    let params = ["dhparams_2048.pem", "dhparams_4096.pem"];

    for path in params {
        let mut builder = config_builder(&security::DEFAULT).unwrap();
        let path = format!("benches/utils/{}", path);
        let path = Path::new(&path);
        let bytes = get_file_as_byte_vec(path);

        group.bench_function(format!("add_dhparams-{:?}", path.file_name()), move |b| {
            b.iter(|| {
                builder.add_dhparams(&bytes).unwrap();
            });
        });
    }

    group.finish();
}

fn get_file_as_byte_vec(path: &Path) -> Vec<u8> {
    let mut f = File::open(path).expect("no file found");
    let metadata = std::fs::metadata(path).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read_exact(&mut buffer).expect("buffer overflow");

    buffer
}

criterion_group!(benches, dh_params);
criterion_main!(benches);
