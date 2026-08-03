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

#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn send_and_recv_vectored() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let connector = TlsConnector::new(common::client_config()?.build()?);
    let acceptor = TlsAcceptor::new(common::server_config()?.build()?);

    let (mut client, mut server) =
        common::run_negotiate(&connector, client_stream, &acceptor, server_stream).await?;

    {
        use tokio::io::AsyncWrite;
        assert!(client.is_write_vectored());
    }

    let bufs = [
        io::IoSlice::new(b"hello "),
        io::IoSlice::new(b""),
        io::IoSlice::new(b"vectored "),
        io::IoSlice::new(b"world"),
    ];
    let expected: Vec<u8> = bufs.iter().flat_map(|buf| buf.iter().copied()).collect();

    let written = client.write_vectored(&bufs).await?;
    assert_eq!(written, expected.len());

    let mut received = vec![0; expected.len()];
    server.read_exact(&mut received).await?;
    assert_eq!(expected, received);

    Ok(())
}

#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn send_and_recv_vectored_multiple_records() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let connector = TlsConnector::new(common::client_config()?.build()?);
    let acceptor = TlsAcceptor::new(common::server_config()?.build()?);

    let (mut client, mut server) =
        common::run_negotiate(&connector, client_stream, &acceptor, server_stream).await?;

    // Send a payload larger than the maximum TLS record payload (2^14 bytes),
    // split across multiple buffers, to ensure multiple records and exercise
    // partial writes.
    let expected = LARGE_TEST_DATA;
    let mut received = vec![0; expected.len()];

    let write_all_vectored = async {
        let mut written = 0;
        while written < expected.len() {
            let remaining = &expected[written..];
            let mid = remaining.len().div_ceil(2);
            let (first, second) = remaining.split_at(mid);
            // On a partial write, resume by advancing past the bytes
            // already written rather than repeating the same buffers.
            let bufs = [io::IoSlice::new(first), io::IoSlice::new(second)];
            written += client.write_vectored(&bufs).await?;
        }
        Ok::<_, io::Error>(())
    };

    let (_, read_size) = tokio::try_join!(write_all_vectored, server.read_exact(&mut received))?;
    assert_eq!(expected.len(), read_size);
    assert_eq!(expected, received);

    Ok(())
}

#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn send_vectored_blocked_then_retry() -> Result<(), Box<dyn std::error::Error>> {
    let client = TlsConnector::new(common::client_config()?.build()?);
    let server = TlsAcceptor::new(common::server_config()?.build()?);

    let (server_stream, client_stream) = common::get_streams().await?;
    let client_stream = common::TestStream::new(client_stream);
    let overrides = client_stream.overrides();
    let (mut client, mut server) =
        common::run_negotiate(&client, client_stream, &server, server_stream).await?;

    // Setup the underlying stream to block on the next write
    overrides.next_write(Some(Box::new(|_, ctx, _| {
        ctx.waker().wake_by_ref();
        Pending
    })));

    let bufs = [
        io::IoSlice::new(b"blocked "),
        io::IoSlice::new(b"then retried"),
    ];
    let expected: Vec<u8> = bufs.iter().flat_map(|buf| buf.iter().copied()).collect();

    // The first write blocks, so the future retries with the same buffers
    // once the underlying stream is writable again.
    let written = client.write_vectored(&bufs).await?;
    assert_eq!(written, expected.len());

    let mut received = vec![0; expected.len()];
    server.read_exact(&mut received).await?;
    assert_eq!(expected, received);

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
