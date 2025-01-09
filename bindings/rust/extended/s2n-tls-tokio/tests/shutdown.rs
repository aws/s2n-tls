// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::error;
use s2n_tls_tokio::{TlsAcceptor, TlsConnector, TlsStream};
use std::{
    convert::TryFrom,
    io,
    sync::Arc,
    task::Poll::{Pending, Ready},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time,
};

pub mod common;

async fn read_until_shutdown<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut TlsStream<S>,
) -> Result<(), std::io::Error> {
    let mut received = [0; 1];
    // Zero bytes read indicates EOF
    while stream.read(&mut received).await? != 0 {}
    stream.shutdown().await
}

async fn write_until_shutdown<S: AsyncWrite + Unpin>(stream: &mut S) -> Result<(), std::io::Error> {
    let sent = [0; 1];
    loop {
        if let Err(err) = stream.write(&sent).await {
            let tls_err = error::Error::try_from(err).unwrap();
            assert_eq!(tls_err.kind(), error::ErrorType::ConnectionClosed);
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

/// Reading and writing handles should both respond to a peer's "close notify"
/// appropriately. The read handle should immediately exit and writing should
/// fail with a "connection closed" error.
#[tokio::test]
async fn shutdown_after_split() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let client = TlsConnector::new(common::client_config_tls12()?.build()?);
    let server = TlsAcceptor::new(common::server_config_tls12()?.build()?);

    let (client, mut server) =
        common::run_negotiate(&client, client_stream, &server, server_stream).await?;

    let (mut client_reader, mut client_writer) = tokio::io::split(client);

    let mut received = [0; 1];

    // All tasks must cleanly exit. try_join will return as soon as an error
    // occurs, so if the result is any error then the test has failed.
    tokio::try_join!(
        server.shutdown(),
        client_reader.read(&mut received),
        write_until_shutdown(&mut client_writer),
    )?;
    Ok(())
}

/// Reading and writing handles should both respond to a peers "close notify"
/// appropriately. TLS1.3 connections have "half close behavior". The read
/// handle should immediately exit, but the write handle can continue to write
/// until explicitly shutdown. After both client handles have shutdown, the
/// server should cleanly exit.
#[tokio::test]
async fn shutdown_after_halfclose_split() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let client = TlsConnector::new(common::client_config()?.build()?);
    let server = TlsAcceptor::new(common::server_config()?.build()?);

    let (client, mut server) =
        common::run_negotiate(&client, client_stream, &server, server_stream).await?;

    let (mut client_reader, mut client_writer) = tokio::io::split(client);

    let close_notify_recvd = Arc::new(tokio::sync::Notify::new());
    let close_notify_recvd_clone = close_notify_recvd.clone();

    let mut received = [0; 1];

    // all tasks must complete, and must complete successfully
    // the client tasks will panic if an error is encountered, so those don't
    // need to be checked.
    let (server, _, _) = tokio::join!(
        server.shutdown(),
        async {
            let bytes_read = client_reader.read(&mut received).await.unwrap();
            // 0 bytes read indicate that we returned because of close notify
            assert_eq!(bytes_read, 0);
            // signal the writer task that close notify received
            close_notify_recvd.notify_one();
        },
        async {
            // wait for the connection to receive "close notify" from peer
            close_notify_recvd_clone.notified().await;
            // confirm that we can write even after receiving the shutdown from
            // the server
            client_writer
                .write_all("random bytes".as_bytes())
                .await
                .unwrap();
            client_writer.flush().await.unwrap();
            // shutdown
            client_writer.shutdown().await.unwrap()
        }
    );
    // make sure the server shutdown cleanly
    assert!(server.is_ok());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn shutdown_with_blinding() -> Result<(), Box<dyn std::error::Error>> {
    let clock = common::TokioTime::default();
    let mut server_config = common::server_config()?;
    server_config.set_monotonic_clock(clock)?;

    let client = TlsConnector::new(common::client_config()?.build()?);
    let server = TlsAcceptor::new(server_config.build()?);

    let (server_stream, client_stream) = common::get_streams().await?;
    let server_stream = common::TestStream::new(server_stream);
    let overrides = server_stream.overrides();
    let (mut client, mut server) =
        common::run_negotiate(&client, client_stream, &server, server_stream).await?;

    // Setup a bad record for the next read
    overrides.next_read(Some(Box::new(|_, _, buf| {
        // Parsing the header is one of the blinded operations
        // in s2n_recv, so provide a malformed header.
        let zeroed_header = [23, 0, 0, 0, 0];
        buf.put_slice(&zeroed_header);
        Ok(()).into()
    })));

    // Trigger the blinded error
    let mut received = [0; 1];
    let result = server.read_exact(&mut received).await;
    assert!(result.is_err());

    let time_start = time::Instant::now();
    let result = server.shutdown().await;
    let time_elapsed = time_start.elapsed();

    // Shutdown MUST NOT complete faster than minimal blinding time.
    assert!(time_elapsed > common::MIN_BLINDING_SECS);

    // Server MUST eventually successfully shutdown
    assert!(result.is_ok());

    // Shutdown MUST have sent the close_notify message needed for EOF.
    let mut received = [0; 1];
    assert!(client.read(&mut received).await? == 0);

    Ok(())
}

#[tokio::test(start_paused = true)]
async fn shutdown_with_poll_blinding() -> Result<(), Box<dyn std::error::Error>> {
    let clock = common::TokioTime::default();
    let mut server_config = common::server_config()?;
    server_config.set_monotonic_clock(clock)?;

    let client = TlsConnector::new(common::client_config()?.build()?);
    let server = TlsAcceptor::new(server_config.build()?);

    let (server_stream, client_stream) = common::get_streams().await?;
    let server_stream = common::TestStream::new(server_stream);
    let overrides = server_stream.overrides();
    let (_, mut server) =
        common::run_negotiate(&client, client_stream, &server, server_stream).await?;

    // Setup a bad record for the next read
    overrides.next_read(Some(Box::new(|_, _, buf| {
        // Parsing the header is one of the blinded operations
        // in s2n_recv, so provide a malformed header.
        let zeroed_header = [23, 0, 0, 0, 0];
        buf.put_slice(&zeroed_header);
        Ok(()).into()
    })));

    // Trigger the blinded error
    let mut received = [0; 1];
    let result = server.read_exact(&mut received).await;
    assert!(result.is_err());

    let time_start = time::Instant::now();
    let result = server.apply_blinding().await;
    let time_elapsed = time_start.elapsed();

    // poll_blinding MUST NOT complete faster than minimal blinding time.
    assert!(time_elapsed > common::MIN_BLINDING_SECS);

    // poll_blinding MUST eventually complete
    assert!(result.is_ok());

    Ok(())
}

#[tokio::test]
async fn shutdown_with_tcp_error() -> Result<(), Box<dyn std::error::Error>> {
    let client = TlsConnector::new(common::client_config()?.build()?);
    let server = TlsAcceptor::new(common::server_config()?.build()?);

    let (server_stream, client_stream) = common::get_streams().await?;
    let server_stream = common::TestStream::new(server_stream);
    let overrides = server_stream.overrides();

    let (_, mut server) =
        common::run_negotiate(&client, client_stream, &server, server_stream).await?;

    // The underlying stream should return a unique error on shutdown
    overrides.next_shutdown(Some(Box::new(|_, _| {
        Ready(Err(io::Error::new(io::ErrorKind::Other, common::TEST_STR)))
    })));

    // Shutdown should complete with the correct error from the underlying stream
    let result = server.shutdown().await;
    let error = result.unwrap_err().into_inner().unwrap();
    assert!(error.to_string() == common::TEST_STR);

    Ok(())
}

#[tokio::test]
async fn shutdown_with_tls_error_and_tcp_error() -> Result<(), Box<dyn std::error::Error>> {
    let client = TlsConnector::new(common::client_config()?.build()?);
    let server = TlsAcceptor::new(common::server_config()?.build()?);

    let (server_stream, client_stream) = common::get_streams().await?;
    let server_stream = common::TestStream::new(server_stream);
    let overrides = server_stream.overrides();

    let (_, mut server) =
        common::run_negotiate(&client, client_stream, &server, server_stream).await?;

    // Both s2n_shutdown_send and the underlying stream should error on shutdown
    overrides.next_write(Some(Box::new(|_, _, _| {
        Ready(Err(io::Error::from(io::ErrorKind::Other)))
    })));
    overrides.next_shutdown(Some(Box::new(|_, _| {
        Ready(Err(io::Error::new(io::ErrorKind::Other, common::TEST_STR)))
    })));

    // Shutdown should complete with the correct error from s2n_shutdown_send
    let result = server.shutdown().await;
    let io_error = result.unwrap_err();
    let error: error::Error = io_error.try_into()?;
    // Any non-blocking read error is translated as "IOError"
    assert!(error.kind() == error::ErrorType::IOError);

    // Even if s2n_shutdown_send fails, we need to close the underlying stream.
    // Make sure we called our mock shutdown, consuming it.
    assert!(overrides.is_consumed());

    Ok(())
}

#[tokio::test]
async fn shutdown_with_tls_error_and_tcp_delay() -> Result<(), Box<dyn std::error::Error>> {
    let client = TlsConnector::new(common::client_config()?.build()?);
    let server = TlsAcceptor::new(common::server_config()?.build()?);

    let (server_stream, client_stream) = common::get_streams().await?;
    let server_stream = common::TestStream::new(server_stream);
    let overrides = server_stream.overrides();

    let (mut client, mut server) =
        common::run_negotiate(&client, client_stream, &server, server_stream).await?;

    // We want s2n_shutdown_send to produce an error on write
    overrides.next_write(Some(Box::new(|_, _, _| {
        Ready(Err(io::Error::from(io::ErrorKind::Other)))
    })));

    // The underlying stream should initially return Pending, delaying shutdown
    overrides.next_shutdown(Some(Box::new(|_, ctx| {
        ctx.waker().wake_by_ref();
        Pending
    })));

    // Shutdown should complete with the correct error from s2n_shutdown_send
    let result = server.shutdown().await;
    let io_error = result.unwrap_err();
    let error: error::Error = io_error.try_into()?;
    // Any non-blocking read error is translated as "IOError"
    assert!(error.kind() == error::ErrorType::IOError);

    // Even if s2n_shutdown_send fails, we need to close the underlying stream.
    // Make sure we at least called our mock shutdown, consuming it.
    assert!(overrides.is_consumed());

    // Since s2n_shutdown_send failed, we should NOT have sent a close_notify.
    // Make sure the peer doesn't receive a close_notify.
    // If this is not true, then we're incorrectly calling s2n_shutdown_send
    // again after an error.
    let mut received = [0; 1];
    let io_error = client.read(&mut received).await.unwrap_err();
    let error: error::Error = io_error.try_into()?;
    assert!(error.kind() == error::ErrorType::ConnectionClosed);

    Ok(())
}
