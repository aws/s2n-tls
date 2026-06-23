// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls_tokio::{TlsAcceptor, TlsConnector, TlsStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub mod common;

const TEST_DATA: &[u8] = "hello world".as_bytes();

// Decompose an established stream with into_parts and reassemble it with
// from_parts, then confirm the reassembled stream still sends and receives over
// the same negotiated session.
#[tokio::test]
async fn into_parts_from_parts_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;
    let connector = TlsConnector::new(common::client_config()?.build()?);
    let acceptor = TlsAcceptor::new(common::server_config()?.build()?);
    let (mut client, server) =
        common::run_negotiate(&connector, client_stream, &acceptor, server_stream).await?;

    // Take the server stream apart and put it back together.
    let (conn, tcp) = server.into_parts();
    let mut server = TlsStream::from_parts(conn, tcp);

    // The reassembled stream continues to work on the same session.
    client.write_all(TEST_DATA).await?;
    let mut received = [0; TEST_DATA.len()];
    assert_eq!(server.read_exact(&mut received).await?, TEST_DATA.len());
    assert_eq!(TEST_DATA, received);

    Ok(())
}

// Send data before into_parts and read it after from_parts. Data in flight at
// the handoff lives in the Connection's buffer or the moved socket, both of
// which are carried across by into_parts/from_parts, so this confirms it
// survives the handoff.
#[tokio::test]
async fn into_parts_preserves_buffered_data() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;
    let connector = TlsConnector::new(common::client_config()?.build()?);
    let acceptor = TlsAcceptor::new(common::server_config()?.build()?);
    let (mut client, mut server) =
        common::run_negotiate(&connector, client_stream, &acceptor, server_stream).await?;

    // Client sends before the handoff, and the server reads enough to pull the
    // record off the socket and into the Connection's buffer.
    client.write_all(TEST_DATA).await?;
    client.flush().await?;
    let mut received = [0; TEST_DATA.len()];
    server.read_exact(&mut received).await?;
    assert_eq!(TEST_DATA, received);

    // A second message is sent before the stream is taken apart.
    client.write_all(TEST_DATA).await?;
    client.flush().await?;

    // Take the server stream apart and put it back together.
    let (conn, tcp) = server.into_parts();
    let mut server = TlsStream::from_parts(conn, tcp);

    // Ensure data sent before the handoff is still readable afterwards.
    let mut received = [0; TEST_DATA.len()];
    assert_eq!(server.read_exact(&mut received).await?, TEST_DATA.len());
    assert_eq!(TEST_DATA, received);

    Ok(())
}
