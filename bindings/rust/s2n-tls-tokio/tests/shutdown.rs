// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::error;
use s2n_tls_tokio::{TlsAcceptor, TlsConnector, TlsStream};
use std::convert::TryFrom;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    join, time,
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

#[tokio::test]
async fn shutdown_after_split() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let client = TlsConnector::new(common::client_config()?.build()?);
    let server = TlsAcceptor::new(common::server_config()?.build()?);

    let (client, mut server) =
        common::run_negotiate(&client, client_stream, &server, server_stream).await?;

    let (mut client_reader, mut client_writer) = tokio::io::split(client);

    let mut received = [0; 1];

    // ignore any shutdown errors in case things go wrong
    let _ = tokio::try_join!(
        server.shutdown(),
        client_reader.read(&mut received),
        write_until_shutdown(&mut client_writer),
    );

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

    // Trigger a blinded error for the server.
    overrides.next_read(Some(Box::new(|_, _, buf| {
        // Parsing the header is one of the blinded operations
        // in s2n_recv, so provide a malformed header.
        let zeroed_header = [23, 0, 0, 0, 0];
        buf.put_slice(&zeroed_header);
        Ok(()).into()
    })));
    let mut received = [0; 1];
    let result = server.read_exact(&mut received).await;
    assert!(result.is_err());

    // Shutdown MUST NOT complete faster than minimal blinding time.
    let (timeout, _) = join!(
        time::timeout(common::MIN_BLINDING_SECS, server.shutdown()),
        time::timeout(common::MIN_BLINDING_SECS, read_until_shutdown(&mut client)),
    );
    assert!(timeout.is_err());

    // Shutdown MUST eventually complete after blinding.
    //
    // We check for completion, but not for success. At the moment, the
    // call to s2n_shutdown will fail due to issues in the underlying C library.
    let (timeout, _) = join!(
        time::timeout(common::MAX_BLINDING_SECS, server.shutdown()),
        time::timeout(common::MAX_BLINDING_SECS, read_until_shutdown(&mut client)),
    );
    assert!(timeout.is_ok());

    Ok(())
}
