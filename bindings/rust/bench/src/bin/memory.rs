// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bench::{
    ConnectedBuffer, CryptoConfig, HandshakeType, Mode, OpenSslConnection, RustlsConnection,
    S2NConnection, TlsConnPair, TlsConnection,
};
use std::{error::Error, fs::create_dir_all};
use structopt::{clap::arg_enum, StructOpt};

arg_enum! {
    enum MemoryBenchTarget {
        Client,
        Server,
        Pair,
    }
}

/// Bench the memory taken by either a client, server, or pair of connections
fn memory_bench<T: TlsConnection>(opt: &Opt) -> Result<(), Box<dyn Error>> {
    let reuse_config: bool = opt.reuse_config.parse()?;
    let shrink_buffers: bool = opt.shrink_buffers.parse()?;

    let dir_name = match opt.mode {
        MemoryBenchTarget::Client => format!("{}_client", T::name()),
        MemoryBenchTarget::Server => format!("{}_server", T::name()),
        MemoryBenchTarget::Pair => format!("{}_pair", T::name()),
    };

    println!("testing {dir_name}");

    // create the directories that will hold memory snapshots
    create_dir_all(format!("target/memory/{dir_name}")).unwrap();
    create_dir_all("target/memory/xtree").unwrap();

    // create space to store TlsConnections
    const BENCH_SIZE: usize = 100;
    let mut connections = Vec::new();
    match opt.mode {
        MemoryBenchTarget::Client | MemoryBenchTarget::Server => {
            connections.reserve_exact(BENCH_SIZE)
        }
        // for each connection pair, need to save two connections
        MemoryBenchTarget::Pair => connections.reserve_exact(BENCH_SIZE * 2),
    };

    // reserve space for buffers before benching
    // shrink buffers before and after handshake to keep memory used net zero
    let mut buffers: Vec<ConnectedBuffer> = (0..BENCH_SIZE).map(|_| {
        let mut buffer = ConnectedBuffer::new();
        buffer.shrink();
        buffer
    }).collect();

    // handshake one harness to initalize libraries
    let mut conn_pair = TlsConnPair::<T, T>::default();
    conn_pair.handshake().unwrap();

    // make configs
    let client_config = T::make_config(
        Mode::Client,
        CryptoConfig::default(),
        HandshakeType::default(),
    )?;
    let server_config = T::make_config(
        Mode::Server,
        CryptoConfig::default(),
        HandshakeType::default(),
    )?;

    // tell valgrind/massif to take initial memory snapshot
    crabgrind::monitor_command(format!("snapshot target/memory/{dir_name}/0.snapshot")).unwrap();

    // make and handshake conn pairs
    for i in 1..BENCH_SIZE + 1 {
        // make conn pair
        let mut conn_pair;
        if reuse_config {
            let client_conn = T::new_from_config(&client_config, buffers.pop().unwrap())?;
            let server_conn = T::new_from_config(
                &server_config,
                client_conn.connected_buffer().clone_inverse(),
            )?;
            conn_pair = TlsConnPair::wrap(client_conn, server_conn);
        } else {
            conn_pair = TlsConnPair::<T, T>::new(
                CryptoConfig::default(),
                HandshakeType::default(),
                buffers.pop().unwrap(),
            )?;
        }
        
        // handshake conn pair
        conn_pair.handshake()?;
        if shrink_buffers {
            conn_pair.shrink_connection_buffers();
        }
        conn_pair.shrink_connected_buffers();

        // store things that are bench targets to prevent dropping
        match opt.mode {
            MemoryBenchTarget::Client => connections.push(conn_pair.split().0),
            MemoryBenchTarget::Server => connections.push(conn_pair.split().1),
            MemoryBenchTarget::Pair => {
                let (client, server) = conn_pair.split();
                connections.push(client);
                connections.push(server);
            }
        };

        // take memory snapshot
        crabgrind::monitor_command(format!("snapshot target/memory/{dir_name}/{i}.snapshot"))?;
    }

    // take xtree snapshot
    crabgrind::monitor_command(format!("xtmemory target/memory/xtree/{dir_name}.out"))?;

    Ok(())
}

#[derive(StructOpt)]
struct Opt {
    #[structopt()]
    lib_name: Option<String>,

    #[structopt(possible_values = &MemoryBenchTarget::variants(), case_insensitive = true, default_value = "pair")]
    mode: MemoryBenchTarget,

    #[structopt(long, default_value = "true")]
    reuse_config: String,

    #[structopt(long, default_value = "true")]
    shrink_buffers: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    assert!(!cfg!(debug_assertions), "need to run in release mode");

    let opt = Opt::from_args();

    match &opt.lib_name {
        Some(lib_name) => match lib_name.as_str() {
            "s2n-tls" => memory_bench::<S2NConnection>(&opt)?,
            "rustls" => memory_bench::<RustlsConnection>(&opt)?,
            "openssl" => memory_bench::<OpenSslConnection>(&opt)?,
            _ => panic!("invalid library"),
        },
        None => {
            memory_bench::<S2NConnection>(&opt)?;
            memory_bench::<OpenSslConnection>(&opt)?;
            memory_bench::<RustlsConnection>(&opt)?;
        }
    }

    Ok(())
}
