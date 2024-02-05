// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "openssl")]
use bench::OpenSslConnection;
#[cfg(feature = "rustls")]
use bench::RustlsConnection;
use bench::{
    ConnectedBuffer, CryptoConfig, HandshakeType, Mode, S2NConnection, TlsConnPair, TlsConnection,
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

impl std::fmt::Debug for MemoryBenchTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                MemoryBenchTarget::Client => "client",
                MemoryBenchTarget::Server => "server",
                MemoryBenchTarget::Pair => "pair",
            }
        )
    }
}

/// Bench the memory taken by either a client, server, or pair of connections
fn memory_bench<T: TlsConnection>(opt: &Opt) -> Result<(), Box<dyn Error>> {
    let reuse_config: bool = opt.reuse_config.parse()?;
    let shrink_buffers: bool = opt.shrink_buffers.parse()?;

    // store data in directory based on params, target, and library name
    let params_string = match (reuse_config, shrink_buffers) {
        (false, false) => "no-optimizations",
        (true, false) => "reuse-config",
        (false, true) => "shrink-buffers",
        (true, true) => "reuse-config-shrink-buffers",
    };
    let dir_name = &format!(
        "target/memory/{params_string}/{:?}/{}",
        opt.target,
        T::name()
    );

    println!("benching {:?} {} {}", opt.target, T::name(), params_string);

    // create the directory that will hold memory snapshots and xtree
    create_dir_all(dir_name).unwrap();

    // create space to store TlsConnections
    const BENCH_SIZE: usize = 100;
    let mut connections = Vec::new();
    match opt.target {
        MemoryBenchTarget::Client | MemoryBenchTarget::Server => {
            connections.reserve_exact(BENCH_SIZE)
        }
        // for each connection pair, need to save two connections
        MemoryBenchTarget::Pair => connections.reserve_exact(BENCH_SIZE * 2),
    };

    // reserve space for buffers before benching
    // shrink buffers before and after handshake to keep memory net zero
    let mut buffers: Vec<ConnectedBuffer> = (0..BENCH_SIZE)
        .map(|_| {
            let mut buffer = ConnectedBuffer::new();
            buffer.shrink();
            buffer
        })
        .collect();

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
    crabgrind::monitor_command(format!("snapshot {dir_name}/0.snapshot")).unwrap();

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

        // store bench target(s)
        let (client, server) = conn_pair.split();
        match opt.target {
            MemoryBenchTarget::Client => connections.push(client),
            MemoryBenchTarget::Server => connections.push(server),
            MemoryBenchTarget::Pair => {
                connections.push(client);
                connections.push(server);
            }
        };

        // take memory snapshot
        crabgrind::monitor_command(format!("snapshot {dir_name}/{i}.snapshot"))?;
    }

    // take xtree snapshot
    crabgrind::monitor_command(format!("xtmemory {dir_name}/xtree.out"))?;

    Ok(())
}

#[derive(StructOpt)]
/// Generate TLS connections and record memory used after each connection.
/// Snapshots are stored in target/memory/[params]/[target]
struct Opt {
    /// Which connection(s) to memory bench
    #[structopt(possible_values = &MemoryBenchTarget::variants(), case_insensitive = true, default_value = "pair")]
    target: MemoryBenchTarget,

    /// If set, run benches with only a specific library
    #[structopt()]
    lib_name: Option<String>,

    /// Reuse configs when making connections
    #[structopt(long, default_value = "true")]
    reuse_config: String,

    /// Shrink connection buffers after handshake to simulate idle connection
    #[structopt(long, default_value = "true")]
    shrink_buffers: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    assert!(!cfg!(debug_assertions), "need to run in release mode");

    let opt = Opt::from_args();

    match &opt.lib_name {
        Some(lib_name) => match lib_name.as_str() {
            "s2n-tls" => memory_bench::<S2NConnection>(&opt)?,
            #[cfg(feature = "rustls")]
            "rustls" => memory_bench::<RustlsConnection>(&opt)?,
            #[cfg(feature = "openssl")]
            "openssl" => memory_bench::<OpenSslConnection>(&opt)?,
            _ => panic!("invalid library"),
        },
        None => {
            memory_bench::<S2NConnection>(&opt)?;
            #[cfg(feature = "rustls")]
            memory_bench::<RustlsConnection>(&opt)?;
            #[cfg(feature = "openssl")]
            memory_bench::<OpenSslConnection>(&opt)?;
        }
    }

    Ok(())
}
