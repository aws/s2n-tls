// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::raw::error;
use s2n_tls_tokio::{TlsAcceptor, TlsConnector, TlsStream};
use std::convert::TryFrom;
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

mod common;

async fn read_until_shutdown(stream: &mut TlsStream<TcpStream>) -> Result<(), std::io::Error> {
    let mut received = [0; 1];
    // Zero bytes read indicates EOF
    while stream.read(&mut received).await? != 0 {}
    stream.shutdown().await
}

async fn write_until_shutdown<S: AsyncWrite + Unpin>(stream: &mut S) -> Result<(), std::io::Error> {
    let sent = [0; 1];
    loop {
        let r = stream.write(&sent).await;
        if r.is_ok() {
            continue;
        } else {
            let tls_err = error::Error::try_from(r.unwrap_err()).unwrap();
            assert_eq!(tls_err.kind(), Some(error::ErrorType::ConnectionClosed));
            break;
        }
    }
    stream.shutdown().await
}

#[tokio::test]
async fn client_initiated_shutdown() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let client = TlsConnector::new(common::client_config()?.build()?);
    let server = TlsAcceptor::new(common::server_config()?.build()?);

    let (mut client, mut server) =
        common::run_negotiate(&client, client_stream, &server, server_stream).await?;

    tokio::try_join!(read_until_shutdown(&mut server), client.shutdown())?;

    Ok(())
}

#[tokio::test]
async fn server_initiated_shutdown() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let client = TlsConnector::new(common::client_config()?.build()?);
    let server = TlsAcceptor::new(common::server_config()?.build()?);

    let (mut client, mut server) =
        common::run_negotiate(&client, client_stream, &server, server_stream).await?;

    tokio::try_join!(read_until_shutdown(&mut client), server.shutdown())?;

    Ok(())
}

#[tokio::test]
async fn shutdown_after_split() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let client = TlsConnector::new(common::client_config()?.build()?);
    let server = TlsAcceptor::new(common::server_config()?.build()?);

    let (client, mut server) =
        common::run_negotiate(&client, client_stream, &server, server_stream).await?;

    let (mut client_reader, mut client_writer) = tokio::io::split(client);

    let mut received = [0; 1];
    tokio::try_join!(
        server.shutdown(),
        client_reader.read(&mut received),
        write_until_shutdown(&mut client_writer),
    )?;

    Ok(())
}
