// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use rand::Rng;
use s2n_tls::{
    config::Config,
    connection::{Connection, ModifiedBuilder},
    enums::{ClientAuthType, Mode, Version},
    error::{Error, ErrorType},
    pool::ConfigPoolBuilder,
    security::DEFAULT_TLS13,
};
use s2n_tls_tokio::{TlsAcceptor, TlsConnector};
use std::{collections::VecDeque, time::Duration};
use tokio::time;

pub mod common;

#[tokio::test]
async fn handshake_basic() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let client = TlsConnector::new(common::client_config()?.build()?);
    let server = TlsAcceptor::new(common::server_config()?.build()?);

    let (client_result, server_result) =
        common::run_negotiate(&client, client_stream, &server, server_stream).await?;

    for tls in [client_result, server_result] {
        // Security policy ensures TLS1.3.
        assert_eq!(tls.as_ref().actual_protocol_version()?, Version::TLS13);
        // Handshake types may change, but will at least be negotiated.
        assert!(tls.as_ref().handshake_type()?.contains("NEGOTIATED"));
        // Cipher suite may change, so just makes sure we can retrieve it.
        assert!(tls.as_ref().cipher_suite().is_ok());
        assert!(tls.as_ref().selected_curve().is_ok());
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_with_pool_multithread() -> Result<(), Box<dyn std::error::Error>> {
    const COUNT: usize = 20;
    const CLIENT_LIMIT: usize = 3;

    let client_config = common::client_config()?.build()?;
    let server_config = common::server_config()?.build()?;

    let mut client_pool = ConfigPoolBuilder::new(Mode::Client, client_config);
    client_pool.set_max_pool_size(CLIENT_LIMIT);

    let client_pool = client_pool.build();
    let server_pool = ConfigPoolBuilder::new(Mode::Server, server_config).build();

    let client = TlsConnector::new(client_pool.clone());
    let server = TlsAcceptor::new(server_pool.clone());

    let mut tasks = VecDeque::new();
    for _ in 0..COUNT {
        let client = client.clone();
        let server = server.clone();
        tasks.push_back(tokio::spawn(async move {
            // Start each handshake at a randomly determined time
            let rand = rand::thread_rng().gen_range(0..50);
            time::sleep(Duration::from_millis(rand)).await;

            let (server_stream, client_stream) = common::get_streams().await.unwrap();
            common::run_negotiate(&client, client_stream, &server, server_stream).await
        }));
    }

    for task in tasks {
        task.await??;
    }
    Ok(())
}

#[tokio::test]
async fn handshake_with_connection_config() -> Result<(), Box<dyn std::error::Error>> {
    // Setup the client with a method
    fn with_client_auth(conn: &mut Connection) -> Result<&mut Connection, Error> {
        conn.set_client_auth_type(ClientAuthType::Optional)
    }
    let client_builder = ModifiedBuilder::new(common::client_config()?.build()?, with_client_auth);

    // Setup the server with a closure
    let server_builder = ModifiedBuilder::new(common::server_config()?.build()?, |conn| {
        conn.set_client_auth_type(ClientAuthType::Optional)
    });

    let client = TlsConnector::new(client_builder);
    let server = TlsAcceptor::new(server_builder);

    let (server_stream, client_stream) = common::get_streams().await?;
    let (client_result, server_result) =
        common::run_negotiate(&client, client_stream, &server, server_stream).await?;

    for tls in [client_result, server_result] {
        assert!(tls.as_ref().handshake_type()?.contains("CLIENT_AUTH"));
    }

    Ok(())
}

#[tokio::test]
async fn handshake_with_connection_config_with_pool() -> Result<(), Box<dyn std::error::Error>> {
    fn with_client_auth(conn: &mut Connection) -> Result<&mut Connection, Error> {
        conn.set_client_auth_type(ClientAuthType::Optional)
    }
    let client_builder = ModifiedBuilder::new(common::client_config()?.build()?, with_client_auth);
    let server_pool =
        ConfigPoolBuilder::new(Mode::Server, common::server_config()?.build()?).build();
    let server_builder = ModifiedBuilder::new(server_pool, with_client_auth);

    let client = TlsConnector::new(client_builder);
    let server = TlsAcceptor::new(server_builder);

    for _ in 0..5 {
        let (server_stream, client_stream) = common::get_streams().await?;
        let (_, server_result) =
            common::run_negotiate(&client, client_stream, &server, server_stream).await?;
        assert!(server_result
            .as_ref()
            .handshake_type()?
            .contains("CLIENT_AUTH"));
    }

    Ok(())
}

#[tokio::test]
async fn handshake_error() -> Result<(), Box<dyn std::error::Error>> {
    // Config::default() does not include any RSA certificates,
    // but only provides TLS1.2 cipher suites that require RSA auth.
    // The server will fail to choose a cipher suite, but
    // S2N_ERR_CIPHER_NOT_SUPPORTED is specifically excluded from blinding.
    let bad_config = Config::default();
    let client_config = common::client_config()?.build()?;
    let server_config = bad_config;

    let client = TlsConnector::new(client_config);
    let server = TlsAcceptor::new(server_config);

    let (server_stream, client_stream) = common::get_streams().await?;
    let result = common::run_negotiate(&client, client_stream, &server, server_stream).await;
    assert!(matches!(result, Err(e) if !e.is_retryable()));

    Ok(())
}

#[tokio::test(start_paused = true)]
async fn handshake_error_with_blinding() -> Result<(), Box<dyn std::error::Error>> {
    let clock = common::TokioTime::default();

    // Config::builder() does not include a trust store.
    // The client will reject the server certificate as untrusted.
    let mut bad_config = Config::builder();
    bad_config.set_security_policy(&DEFAULT_TLS13)?;
    bad_config.set_monotonic_clock(clock)?;
    let client_config = bad_config.build()?;
    let server_config = common::server_config()?.build()?;

    let client = TlsConnector::new(client_config.clone());
    let server = TlsAcceptor::new(server_config.clone());

    // Handshake MUST NOT finish faster than minimal blinding time.
    let (server_stream, client_stream) = common::get_streams().await?;
    let timeout = time::timeout(
        common::MIN_BLINDING_SECS,
        common::run_negotiate(&client, client_stream, &server, server_stream),
    )
    .await;
    assert!(timeout.is_err());

    // Handshake MUST eventually gracefully close after blinding
    let (server_stream, client_stream) = common::get_streams().await?;
    let timeout = time::timeout(
        common::MAX_BLINDING_SECS.mul_f32(1.1),
        common::run_negotiate(&client, client_stream, &server, server_stream),
    )
    .await;
    let result = timeout?;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), ErrorType::ProtocolError);

    Ok(())
}

#[tokio::test]
async fn io_stream_access() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let client_addr = client_stream.local_addr().unwrap();
    let client = TlsConnector::new(common::client_config()?.build()?);
    let server = TlsAcceptor::new(common::server_config()?.build()?);

    let (mut client_result, _server_result) =
        common::run_negotiate(&client, client_stream, &server, server_stream).await?;

    assert_eq!(client_result.get_ref().local_addr().unwrap(), client_addr);
    assert_eq!(client_result.get_mut().local_addr().unwrap(), client_addr);

    Ok(())
}
