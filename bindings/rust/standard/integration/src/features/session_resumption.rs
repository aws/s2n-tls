// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::capability_check::{required_capability, Capability};
use std::time::SystemTime;

use openssl::ssl::{SslContextBuilder, SslMethod, SslVersion};

use tls_harness::{
    cohort::{
        openssl::SessionTicketStorage as OSSLTicketStorage,
        s2n_tls::SessionTicketStorage as S2NTicketStorage, OpenSslConfig, OpenSslConnection,
        S2NConfig, S2NConnection,
    },
    harness::TlsConfigBuilder,
    Mode, SigType, TlsConnPair,
};

use s2n_tls::security::Policy;

const KEY_NAME: &str = "InsecureTestKey";
const KEY_VALUE: [u8; 16] = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3];

/// Builds an s2n-tls client configuration with session ticket support enabled,
/// returning both the config and the associated ticket storage.
fn s2n_client_resumption_config(cert: SigType) -> (S2NTicketStorage, S2NConfig) {
    let ticket_storage = S2NTicketStorage::default();
    let client_config = {
        let mut config = s2n_tls::config::Builder::new_test_config(Mode::Client);
        config
            .set_security_policy(&Policy::from_version("test_all").unwrap())
            .unwrap();
        config.set_trust(cert);
        config.enable_session_tickets(true).unwrap();
        config
            .set_session_ticket_callback(ticket_storage.clone())
            .unwrap();
        config.build().unwrap().into()
    };
    (ticket_storage, client_config)
}

/// Builds an s2n-tls server configuration with session tickets enabled and a
/// deterministic test ticket key installed.
fn s2n_server_resumption_config(cert: SigType) -> S2NConfig {
    let mut config = s2n_tls::config::Builder::new_test_config(Mode::Server);
    config
        .set_security_policy(&Policy::from_version("test_all").unwrap())
        .unwrap();
    config.set_chain(cert);
    config.enable_session_tickets(true).unwrap();
    config
        .add_session_ticket_key(
            KEY_NAME.as_bytes(),
            KEY_VALUE.as_slice(),
            // Use a timestamp in the past so the key is immediately valid.
            SystemTime::UNIX_EPOCH,
        )
        .unwrap();
    config.build().unwrap().into()
}

/// Builds an OpenSSL client config that stores the negotiated session for later
/// resumption, constrained to a single protocol version.
fn openssl_client_resumption_config(
    cert: SigType,
    protocol_version: SslVersion,
) -> (OSSLTicketStorage, OpenSslConfig) {
    let session_ticket_storage = OSSLTicketStorage::default();
    let mut builder = SslContextBuilder::new_test_config(Mode::Client);
    builder.set_trust(cert);
    builder.set_session_cache_mode(openssl::ssl::SslSessionCacheMode::CLIENT);

    // The session callback must be defined inline to satisfy type inference.
    // See: https://github.com/rust-lang/rust/issues/70263
    builder.set_new_session_callback({
        let sts = session_ticket_storage.clone();
        move |_, ticket| {
            let _ = sts.stored_ticket.lock().unwrap().insert(ticket);
        }
    });

    builder.set_security_level(0);

    builder
        .set_min_proto_version(Some(protocol_version))
        .unwrap();
    builder
        .set_max_proto_version(Some(protocol_version))
        .unwrap();

    (session_ticket_storage, builder.build().into())
}

/// Verifies that an s2n-tls client can resume sessions established with an
/// OpenSSL server across supported protocol versions.
#[test]
fn s2n_client_resumption_with_openssl() {
    const PROTOCOL_VERSIONS: &[SslVersion] =
        &[SslVersion::TLS1_2, SslVersion::TLS1_1, SslVersion::TLS1];

    fn s2n_client_case(protocol: SslVersion) -> Result<(), Box<dyn std::error::Error>> {
        let (ticket_storage, client_config) = s2n_client_resumption_config(SigType::Rsa2048);

        // OpenSSL enables session resumption by default.
        let server_config = OpenSslConfig::from({
            let mut builder = SslContextBuilder::new(SslMethod::tls_server())?;
            builder.set_chain(SigType::Rsa2048);
            builder.set_security_level(0);
            builder.set_min_proto_version(Some(protocol)).unwrap();
            builder.set_max_proto_version(Some(protocol)).unwrap();
            builder.build()
        });

        // Initial handshake to generate a session ticket.
        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        pair.handshake()?;
        pair.round_trip_assert(10_000)?;
        pair.shutdown()?;

        // Resume using the previously issued ticket.
        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        let ticket = ticket_storage.get_ticket();
        assert!(!ticket.is_empty());
        pair.client
            .connection_mut()
            .set_session_ticket(&ticket)
            .unwrap();
        pair.handshake()?;
        pair.round_trip_assert(10_000)?;
        assert!(pair.client.connection_mut().resumed());
        pair.shutdown()?;
        Ok(())
    }

    PROTOCOL_VERSIONS.iter().for_each(|version| {
        s2n_client_case(*version).unwrap();
    });
    required_capability(&[Capability::Tls13], || {
        s2n_client_case(SslVersion::TLS1_3).unwrap();
    });
}

/// Verifies that an s2n-tls server can resume sessions established with an
/// OpenSSL client across supported protocol versions.
#[test]
fn s2n_server_resumption_with_openssl() {
    const PROTOCOL_VERSIONS: &[SslVersion] =
        &[SslVersion::TLS1_2, SslVersion::TLS1_1, SslVersion::TLS1];

    fn s2n_server_case(version: SslVersion) -> Result<(), Box<dyn std::error::Error>> {
        let server_config = s2n_server_resumption_config(SigType::Rsa2048);
        let (ticket_storage, client_config) =
            openssl_client_resumption_config(SigType::Rsa2048, version);

        // Initial handshake to generate a session ticket.
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        pair.handshake()?;
        pair.round_trip_assert(10_000)?;
        pair.shutdown()?;

        // Resume using the stored OpenSSL session.
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        let ticket = ticket_storage.get_ticket();
        unsafe { pair.client.ssl_mut().set_session(&ticket)? };
        pair.handshake()?;
        pair.round_trip_assert(10_000)?;
        assert!(pair.server.connection_mut().resumed());
        pair.shutdown()?;
        Ok(())
    }

    PROTOCOL_VERSIONS.iter().for_each(|version| {
        s2n_server_case(*version).unwrap();
    });
    required_capability(&[Capability::Tls13], || {
        s2n_server_case(SslVersion::TLS1_3).unwrap();
    });
}
