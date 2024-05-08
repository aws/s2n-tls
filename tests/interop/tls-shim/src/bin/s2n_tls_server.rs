// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddrV4},
    process::exit,
};
use tls_shim::{s2n_tls_shim::S2NShim, ServerTLS};
use tokio::net::{TcpListener, TcpStream};
use tracing::Level;

use common::InteropTest;

// while it would be convenient to make this function generic over Tls: ServerTls<Stream>
// the rust compiler type inference isn't advanced enough to add send bounds to
// the futures that get inferred.
async fn run_server(
    config: <S2NShim as ServerTLS<TcpStream>>::Config,
    port: u16,
    test: InteropTest,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let server = <S2NShim as ServerTLS<TcpStream>>::acceptor(config);

    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).await?;
    let (stream, peer_addr) = listener.accept().await?;
    tracing::info!("Connection from {:?}", peer_addr);

    let tls = <S2NShim as ServerTLS<TcpStream>>::accept(&server, stream).await?;
    <S2NShim as ServerTLS<TcpStream>>::handle_server_connection(test, tls).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::fmt()
        .with_max_level(Level::INFO)
        .with_ansi(false)
        .init();

    let (test, port) = common::parse_server_arguments();
    let config = match <S2NShim as ServerTLS<TcpStream>>::get_server_config(test)? {
        Some(c) => c,
        // if the test case isn't supported, return 127
        None => exit(127),
    };
    if let Err(e) = run_server(config, port, test).await {
        tracing::error!("test scenario failed: {:?}", e);
        exit(1);
    }
    Ok(())
}
