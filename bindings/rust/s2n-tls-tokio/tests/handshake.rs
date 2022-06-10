// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use rand::Rng;
use s2n_tls::raw::{
    connection::{Connection, ModifiedBuilder},
    enums::{ClientAuthType, Mode, Version},
    error::Error,
    pool::ConfigPoolBuilder,
};
use s2n_tls_tokio::{TlsAcceptor, TlsConnector};
use std::collections::VecDeque;
use tokio::time::{sleep, Duration};

mod common;

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
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_with_pool_multithread() -> Result<(), Box<dyn std::error::Error>> {
    const COUNT: usize = 200;
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
            sleep(Duration::from_millis(rand)).await;

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
