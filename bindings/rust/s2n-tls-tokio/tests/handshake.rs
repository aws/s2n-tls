// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::raw::{
    connection::{Connection, ModifiedBuilder},
    enums::{ClientAuthType, Version},
    error::Error,
};
use s2n_tls_tokio::{TlsAcceptor, TlsConnector};

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
