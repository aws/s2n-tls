// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls_tokio::{TlsAcceptor, TlsConnector, TlsStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

mod common;

async fn listen_for_shutdown(
    stream: &mut TlsStream<TcpStream>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut received = [0; 1];
    // Zero bytes read indicates EOF
    assert_eq!(stream.read(&mut received).await?, 0);
    stream.shutdown().await?;
    Ok(())
}

async fn shutdown(stream: &mut TlsStream<TcpStream>) -> Result<(), Box<dyn std::error::Error>> {
    stream.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn client_initiated_shutdown() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let client = TlsConnector::new(common::client_config()?.build()?);
    let server = TlsAcceptor::new(common::server_config()?.build()?);

    let (mut client, mut server) =
        common::run_negotiate(client, client_stream, server, server_stream).await?;

    tokio::try_join!(listen_for_shutdown(&mut server), shutdown(&mut client))?;

    Ok(())
}

#[tokio::test]
async fn server_initiated_shutdown() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let client = TlsConnector::new(common::client_config()?.build()?);
    let server = TlsAcceptor::new(common::server_config()?.build()?);

    let (mut client, mut server) =
        common::run_negotiate(client, client_stream, server, server_stream).await?;

    tokio::try_join!(listen_for_shutdown(&mut client), shutdown(&mut server))?;

    Ok(())
}
