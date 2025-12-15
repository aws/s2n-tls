// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::time::SystemTime;

use openssl::ssl::{SslContextBuilder, SslVersion};
use s2n_tls::security::Policy;
use tls_harness::{
    cohort::{rustls::RustlsConfigBuilder, OpenSslConnection, RustlsConnection, S2NConnection},
    harness::{TlsConfigBuilderPair, TlsInfo},
    TlsConnPair,
};

#[test]
fn group_with_tls12_resumption() -> Result<(), Box<dyn std::error::Error>> {
    let (client_config, server_config) = {
        let mut configs =
            TlsConfigBuilderPair::<RustlsConfigBuilder, s2n_tls::config::Builder>::default();
        configs
            .server
            .set_security_policy(&Policy::from_version("20190214")?)?
            .add_session_ticket_key(
                b"some key name",
                b"very random material",
                SystemTime::UNIX_EPOCH,
            )?;
        configs
            .client
            .set_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13]);
        configs.build()
    };

    // first handshake, no resumption
    {
        let mut pair: TlsConnPair<RustlsConnection, S2NConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        pair.handshake()?;
        pair.shutdown()?;

        assert!(!pair.server.resumed_connection());
        assert_eq!(
            pair.server.connection().selected_key_exchange_group(),
            Some("secp256r1")
        );
        assert_eq!(
            pair.server.connection().cipher_suite()?,
            "ECDHE-RSA-AES128-GCM-SHA256"
        );
    }

    // second handshake, resumption
    {
        let mut pair: TlsConnPair<RustlsConnection, S2NConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        pair.handshake()?;
        pair.shutdown()?;

        assert!(pair.server.resumed_connection());
        // TODO: Fix this, because it is wrong: https://github.com/aws/s2n-tls/issues/5672
        assert_eq!(
            pair.server.connection().selected_key_exchange_group(),
            Some("secp256r1")
        );
        assert_eq!(
            pair.server.connection().cipher_suite()?,
            "ECDHE-RSA-AES128-GCM-SHA256"
        );
    }

    Ok(())
}

#[test]
fn group_with_rsa_key_exchange() -> Result<(), Box<dyn std::error::Error>> {
    let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
        let mut configs =
            TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
        configs
            .server
            .set_security_policy(&Policy::from_version("20190120")?)?;
        configs
            .client
            .set_cipher_list("TLS_RSA_WITH_AES_128_CBC_SHA")?;
        configs
            .client
            .set_max_proto_version(Some(SslVersion::TLS1_2))?;
        configs.connection_pair()
    };
    pair.handshake()?;
    pair.shutdown()?;

    assert_eq!(pair.server.connection().selected_key_exchange_group(), None);
    assert_eq!(pair.server.connection().cipher_suite()?, "AES128-SHA");

    Ok(())
}
