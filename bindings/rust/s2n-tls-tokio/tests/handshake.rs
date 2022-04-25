// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::raw::connection::Version;
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
        assert_eq!(tls.get_ref().actual_protocol_version()?, Version::TLS13);
        // Handshake types may change, but will at least be negotiated.
        assert!(tls.get_ref().handshake_type()?.contains("NEGOTIATED"));
        // Cipher suite may change, so just makes sure we can retrieve it.
        assert!(tls.get_ref().cipher_suite().is_ok());
    }

    Ok(())
}
