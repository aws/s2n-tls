// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls_tokio::{TlsAcceptor, TlsConnector};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;

const TEST_DATA: &[u8] = "hello world".as_bytes();

#[tokio::test]
async fn send_and_recv_basic() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let connector = TlsConnector::new(common::client_config()?.build()?);
    let acceptor = TlsAcceptor::new(common::server_config()?.build()?);

    let (mut client, mut server) =
        common::run_negotiate(connector, client_stream, acceptor, server_stream).await?;

    assert_eq!(client.write(TEST_DATA).await?, TEST_DATA.len());

    let mut received = [0; TEST_DATA.len()];
    assert_eq!(server.read(&mut received).await?, TEST_DATA.len());
    assert_eq!(TEST_DATA, received);

    Ok(())
}

#[tokio::test]
async fn send_and_recv_multiple_records() -> Result<(), Box<dyn std::error::Error>> {
    // The maximum TLS record payload is 2^14 bytes.
    // Send more to ensure multiple records.
    const LARGE_TEST_DATA: &[u8] = &[5; (1 << 15)];

    let (server_stream, client_stream) = common::get_streams().await?;

    let connector = TlsConnector::new(common::client_config()?.build()?);
    let acceptor = TlsAcceptor::new(common::server_config()?.build()?);

    let (mut client, mut server) =
        common::run_negotiate(connector, client_stream, acceptor, server_stream).await?;

    let mut received = [0; LARGE_TEST_DATA.len()];
    let (write_size, read_size) = tokio::try_join!(
        client.write(LARGE_TEST_DATA),
        server.read_exact(&mut received)
    )?;
    assert_eq!(write_size, read_size);
    assert_eq!(LARGE_TEST_DATA, received);

    Ok(())
}
