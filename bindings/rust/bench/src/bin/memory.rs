// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{
    harness::ConnectedBuffer, CipherSuite, CryptoConfig, ECGroup, OpenSslHarness, RustlsHarness,
    S2NHarness, TlsBenchHarness,
};
use std::{fs::create_dir_all, path::Path};

fn memory_bench<T: TlsBenchHarness>(dir_name: &str) {
    println!("testing {dir_name}");

    if !Path::new(&format!("target/memory/{dir_name}")).is_dir() {
        create_dir_all(format!("target/memory/{dir_name}")).unwrap();
    }

    let mut harnesses = Vec::new();
    harnesses.reserve(100);

    // reserve space for buffers before benching
    let mut buffers = Vec::new();
    buffers.reserve(100);
    for _ in 0..100 {
        buffers.push(ConnectedBuffer::new());
    }

    // handshake one harness to initalize libraries
    let mut harness = T::default().unwrap();
    harness.handshake().unwrap();

    // tell massif to take initial memory snapshot
    crabgrind::monitor_command(format!("snapshot target/memory/{dir_name}/0.snapshot")).unwrap();

    // make and handshake 100 harness
    for i in 1..101 {
        // put new harness directly into harness vec
        harnesses.push(
            T::new(
                &CryptoConfig {
                    cipher_suite: CipherSuite::AES_128_GCM_SHA256,
                    ec_group: ECGroup::X25519,
                },
                buffers.pop().unwrap(), // take ownership of buffer
            )
            .unwrap(),
        );

        // handshake last harness added
        harnesses
            .as_mut_slice()
            .last_mut()
            .unwrap()
            .handshake()
            .unwrap();

        // take memory snapshot
        crabgrind::monitor_command(format!("snapshot target/memory/{dir_name}/{i}.snapshot"))
            .unwrap();
    }
}

fn main() {
    assert!(!cfg!(debug_assertions), "need to run in release mode");

    memory_bench::<S2NHarness>("s2n-tls");
    memory_bench::<RustlsHarness>("rustls");
    memory_bench::<OpenSslHarness>("openssl");
}
