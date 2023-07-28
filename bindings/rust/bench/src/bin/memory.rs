// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{
    harness::ConnectedBuffer, CryptoConfig, HandshakeType, OpenSslConnection, RustlsConnection,
    S2NConnection, TlsConnPair, TlsConnection,
};
use std::{fs::create_dir_all, path::Path};

fn memory_bench<T: TlsConnection>(dir_name: &str) {
    println!("testing {dir_name}");

    if !Path::new(&format!("target/memory/{dir_name}")).is_dir() {
        create_dir_all(format!("target/memory/{dir_name}")).unwrap();
    }

    let mut conn_pairs = Vec::new();
    conn_pairs.reserve(100);

    // reserve space for buffers before benching
    let mut buffers = Vec::new();
    buffers.reserve(100);
    for _ in 0..100 {
        buffers.push(ConnectedBuffer::new());
    }

    // handshake one harness to initalize libraries
    let mut conn_pair = TlsConnPair::<T, T>::default();
    conn_pair.handshake().unwrap();

    // tell massif to take initial memory snapshot
    crabgrind::monitor_command(format!("snapshot target/memory/{dir_name}/0.snapshot")).unwrap();

    // make and handshake 100 connection pairs
    // memory usage stabilizes after first few handshakes
    for i in 1..101 {
        // put new harness directly into harness vec
        conn_pairs.push(
            TlsConnPair::<T, T>::new(
                CryptoConfig::default(),
                HandshakeType::default(),
                buffers.pop().unwrap(), // take ownership of buffer
            )
            .unwrap(),
        );

        // handshake last harness added
        conn_pairs
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

    memory_bench::<S2NConnection>("s2n-tls");
    memory_bench::<RustlsConnection>("rustls");
    memory_bench::<OpenSslConnection>("openssl");
}
