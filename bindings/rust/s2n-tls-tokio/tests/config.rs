// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::raw::{
    connection::Connection,
    enums::{ClientAuthType, Mode, Version},
    error::Error,
};
use s2n_tls_tokio::{config::ConnConfig, TlsAcceptor, TlsConnector};

mod common;

#[tokio::test]
async fn config_with_closure() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let client = TlsConnector::new(|mode| {
        assert_eq!(mode, Mode::Client);
        let mut conn = Connection::new(mode);

        conn.set_config(common::client_config()?.build()?)?;
        conn.set_client_auth_type(ClientAuthType::Optional)?;

        Ok(conn)
    });

    let server = TlsAcceptor::new(|mode| {
        assert_eq!(mode, Mode::Server);
        let mut conn = Connection::new(mode);

        conn.set_config(common::server_config()?.build()?)?;
        conn.set_client_auth_type(ClientAuthType::Optional)?;

        Ok(conn)
    });

    let (client_result, server_result) =
        common::run_negotiate(client, client_stream, server, server_stream).await?;

    for tls in [client_result, server_result] {
        assert_eq!(tls.get_ref().actual_protocol_version()?, Version::TLS13);
        assert!(tls.get_ref().handshake_type()?.contains("CLIENT_AUTH"));
    }

    Ok(())
}

#[tokio::test]
async fn config_with_method() -> Result<(), Box<dyn std::error::Error>> {
    fn new_conn_with_opt_client_auth(mode: Mode) -> Result<Connection, Error> {
        let config = match mode {
            Mode::Server => common::server_config(),
            Mode::Client => common::client_config(),
        }?
        .build()?;
        let mut conn = Connection::new(mode);
        conn.set_config(config)?;
        conn.set_client_auth_type(ClientAuthType::Optional)?;
        Ok(conn)
    }

    let (server_stream, client_stream) = common::get_streams().await?;

    let client = TlsConnector::new(new_conn_with_opt_client_auth);
    let server = TlsAcceptor::new(new_conn_with_opt_client_auth);

    let (client_result, server_result) =
        common::run_negotiate(client, client_stream, server, server_stream).await?;

    for tls in [client_result, server_result] {
        assert_eq!(tls.get_ref().actual_protocol_version()?, Version::TLS13);
        assert!(tls.get_ref().handshake_type()?.contains("CLIENT_AUTH"));
    }

    Ok(())
}

#[tokio::test]
async fn config_with_conn_config() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = common::get_streams().await?;

    let client_config = common::client_config()?.build()?;
    let client_config = ConnConfig::new(client_config, |conn| {
        conn.set_client_auth_type(ClientAuthType::Optional)
    });

    let server_config = common::server_config()?.build()?;
    let server_config = ConnConfig::new(server_config, |conn| {
        conn.set_client_auth_type(ClientAuthType::Optional)
    });

    let client = TlsConnector::new(client_config);
    let server = TlsAcceptor::new(server_config);

    let (client_result, server_result) =
        common::run_negotiate(client, client_stream, server, server_stream).await?;

    for tls in [client_result, server_result] {
        assert_eq!(tls.get_ref().actual_protocol_version()?, Version::TLS13);
        assert!(tls.get_ref().handshake_type()?.contains("CLIENT_AUTH"));
    }

    Ok(())
}
