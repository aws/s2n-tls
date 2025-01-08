// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls_tokio::{TlsAcceptor, TlsConnector};
use std::{io, task::Poll::*};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub mod common;

const TEST_DATA: &[u8] = "hello world".as_bytes();

// The maximum TLS record payload is 2^14 bytes.
// Send more to ensure multiple records.
const LARGE_TEST_DATA: &[u8] = &[5; (1 << 15)];

#[tokio::test]
async fn send_and_recv_basic() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let connector = TlsConnector::new(common::client_config()?.build()?);
    let acceptor = TlsAcceptor::new(common::server_config()?.build()?);

    let (mut client, mut server) =
        common::run_negotiate(&connector, client_stream, &acceptor, server_stream).await?;

    client.write_all(TEST_DATA).await?;

    let mut received = [0; TEST_DATA.len()];
    assert_eq!(server.read_exact(&mut received).await?, TEST_DATA.len());
    assert_eq!(TEST_DATA, received);

    Ok(())
}

#[tokio::test]
async fn send_and_recv_into_vec() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let connector = TlsConnector::new(common::client_config()?.build()?);
    let acceptor = TlsAcceptor::new(common::server_config()?.build()?);

    let (mut client, mut server) =
        common::run_negotiate(&connector, client_stream, &acceptor, server_stream).await?;

    client.write_all(TEST_DATA).await?;

    let mut received = vec![];
    while received.len() < TEST_DATA.len() {
        let bytes_read = server.read_buf(&mut received).await?;
        assert!(bytes_read > 0);
    }
    assert_eq!(TEST_DATA, received);

    Ok(())
}

#[tokio::test]
async fn send_and_recv_multiple_records() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let connector = TlsConnector::new(common::client_config()?.build()?);
    let acceptor = TlsAcceptor::new(common::server_config()?.build()?);

    let (mut client, mut server) =
        common::run_negotiate(&connector, client_stream, &acceptor, server_stream).await?;

    let mut received = [0; LARGE_TEST_DATA.len()];
    let (_, read_size) = tokio::try_join!(
        client.write_all(LARGE_TEST_DATA),
        server.read_exact(&mut received)
    )?;
    assert_eq!(LARGE_TEST_DATA.len(), read_size);
    assert_eq!(LARGE_TEST_DATA, received);

    Ok(())
}

#[tokio::test]
async fn send_and_recv_split() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let connector = TlsConnector::new(common::client_config()?.build()?);
    let acceptor = TlsAcceptor::new(common::server_config()?.build()?);

    let (client, server) =
        common::run_negotiate(&connector, client_stream, &acceptor, server_stream).await?;

    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut server_read, mut server_write) = tokio::io::split(server);

    let mut client_received = [0; LARGE_TEST_DATA.len()];
    let mut server_received = [0; LARGE_TEST_DATA.len()];
    let (_, _, client_bytes, server_bytes) = tokio::try_join!(
        client_write.write_all(LARGE_TEST_DATA),
        server_write.write_all(LARGE_TEST_DATA),
        client_read.read_exact(&mut client_received),
        server_read.read_exact(&mut server_received)
    )?;

    assert_eq!(client_bytes, LARGE_TEST_DATA.len());
    assert_eq!(server_bytes, LARGE_TEST_DATA.len());
    assert_eq!(LARGE_TEST_DATA, client_received);
    assert_eq!(LARGE_TEST_DATA, server_received);

    Ok(())
}

#[tokio::test]
async fn send_error() -> Result<(), Box<dyn std::error::Error>> {
    let client = TlsConnector::new(common::client_config()?.build()?);
    let server = TlsAcceptor::new(common::server_config()?.build()?);

    let (server_stream, client_stream) = common::get_streams().await?;
    let client_stream = common::TestStream::new(client_stream);
    let overrides = client_stream.overrides();
    let (mut client, _) =
        common::run_negotiate(&client, client_stream, &server, server_stream).await?;

    // Setup write to fail
    overrides.next_write(Some(Box::new(|_, _, _| {
        Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
    })));

    // Verify write fails
    let result = client.write_all(TEST_DATA).await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn recv_error() -> Result<(), Box<dyn std::error::Error>> {
    let client = TlsConnector::new(common::client_config()?.build()?);
    let server = TlsAcceptor::new(common::server_config()?.build()?);

    let (server_stream, client_stream) = common::get_streams().await?;
    let client_stream = common::TestStream::new(client_stream);
    let overrides = client_stream.overrides();
    let (mut client, _) =
        common::run_negotiate(&client, client_stream, &server, server_stream).await?;

    // Setup read to fail
    overrides.next_read(Some(Box::new(|_, _, _| {
        Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
    })));

    // Verify read fails
    let mut received = [0; 1];
    let result = client.read_exact(&mut received).await;
    assert!(result.is_err());

    Ok(())
}
