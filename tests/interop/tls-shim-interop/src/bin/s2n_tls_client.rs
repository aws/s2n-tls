// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddrV4}, process::exit,
};
use tls_shim_interop::{s2n_tls_shim::S2NShim, ClientTLS};
use tokio::net::TcpStream;
use tracing::Level;

use common::InteropTest;

async fn run_client<Tls: ClientTLS<TcpStream>>(
    config: Tls::Config,
    port: u16,
    test: InteropTest,
) -> Result<(), Box<dyn Error>> {
    let client = Tls::connector(config);

    let transport_stream =
        TcpStream::connect(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).await?;

    let tls = Tls::connect(&client, transport_stream).await.unwrap();
    Tls::handle_client_connection(test, tls).await.unwrap();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::fmt()
        .with_max_level(Level::INFO)
        .with_ansi(false)
        .init();
    let (test, port) = common::parse_server_arguments();
    let config = match <S2NShim as ClientTLS<TcpStream>>::get_client_config(test)? {
        Some(c) => c,
        None => exit(127),
    };
    run_client::<S2NShim>(config, port, test).await?;
    Ok(())
}
