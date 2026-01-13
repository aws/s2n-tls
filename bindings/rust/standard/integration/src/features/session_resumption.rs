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
    harness::{TlsConfigBuilder, TlsInfo},
    openssl_extension::SslStreamExtension,
    Mode, SigType, TlsConnPair,
};

use s2n_tls::security::Policy;

const KEY_NAME: &str = "InsecureTestKey";
const KEY_VALUE: [u8; 16] = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3];
const PROTOCOL_VERSIONS: &[SslVersion] = &[
    SslVersion::TLS1,
    SslVersion::TLS1_1,
    SslVersion::TLS1_2,
    SslVersion::TLS1_3,
];
const NUM_RESUMED_RECONNECTS: usize = 5;

/// Builds an s2n-tls client configuration with session ticket support enabled,
/// returning both the config and the associated ticket storage.
fn s2n_client_resumption_config(cert: SigType) -> (S2NTicketStorage, S2NConfig) {
    let ticket_storage = S2NTicketStorage::default();
    let client_config = {
        let mut config = s2n_tls::config::Builder::new_test_config(Mode::Client);
        config
            .set_security_policy(&Policy::from_version("20190801").unwrap())
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
    s2n_server_resumption_config_with_key(cert, &KEY_VALUE)
}

/// Builds an s2n-tls server configuration with session tickets enabled and a
/// custom test ticket key installed.
fn s2n_server_resumption_config_with_key(cert: SigType, key_value: &[u8]) -> S2NConfig {
    let mut config = s2n_tls::config::Builder::new_test_config(Mode::Server);
    config
        .set_security_policy(&Policy::from_version("20190801").unwrap())
        .unwrap();
    config.set_chain(cert);
    config.enable_session_tickets(true).unwrap();
    config
        .add_session_ticket_key(
            KEY_NAME.as_bytes(),
            key_value,
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
    fn s2n_client_case(protocol: SslVersion) -> Result<(), Box<dyn std::error::Error>> {
        let (ticket_storage, client_config) = s2n_client_resumption_config(SigType::Rsa2048);

        let server_config = OpenSslConfig::from({
            let mut builder = SslContextBuilder::new_test_config(Mode::Server);
            builder.set_chain(SigType::Rsa2048);
            builder.set_min_proto_version(Some(protocol))?;
            builder.set_max_proto_version(Some(protocol))?;
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
        if *version == SslVersion::TLS1_3 {
            required_capability(&[Capability::Tls13], || {
                s2n_client_case(SslVersion::TLS1_3).unwrap();
            });
        } else {
            s2n_client_case(*version).unwrap();
        }
    });
}

/// Verifies that an s2n-tls server can resume sessions established with an
/// OpenSSL client across supported protocol versions.
#[test]
fn s2n_server_resumption_with_openssl() {
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
        unsafe { pair.client.connection.mut_ssl().set_session(&ticket)? };
        pair.handshake()?;
        pair.round_trip_assert(10_000)?;
        assert!(pair.server.connection_mut().resumed());
        pair.shutdown()?;
        Ok(())
    }

    PROTOCOL_VERSIONS.iter().for_each(|version| {
        if *version == SslVersion::TLS1_3 {
            required_capability(&[Capability::Tls13], || {
                s2n_server_case(SslVersion::TLS1_3).unwrap();
            });
        } else {
            s2n_server_case(*version).unwrap();
        }
    });
}

/// Verifies native s2n↔s2n session resumption behavior in isolation.
/// This serves as a stable baseline independent of OpenSSL.
#[test]
fn s2n_client_resumption_with_s2n_server_tls12() {
    let (ticket_storage, client_config) = s2n_client_resumption_config(SigType::Rsa2048);
    let server_config = s2n_server_resumption_config(SigType::Rsa2048);

    // Initial handshake to generate a session ticket.
    let mut pair: TlsConnPair<S2NConnection, S2NConnection> =
        TlsConnPair::from_configs(&client_config, &server_config);
    pair.handshake().unwrap();
    pair.round_trip_assert(10_000).unwrap();

    assert!(!pair.client.connection().resumed());
    assert!(!pair.server.connection().resumed());
    pair.shutdown().unwrap();

    // Resume using the stored session ticket.
    let mut pair: TlsConnPair<S2NConnection, S2NConnection> =
        TlsConnPair::from_configs(&client_config, &server_config);
    let ticket = ticket_storage.get_ticket();
    assert!(!ticket.is_empty());
    pair.client
        .connection_mut()
        .set_session_ticket(&ticket)
        .unwrap();
    pair.handshake().unwrap();
    pair.round_trip_assert(10_000).unwrap();

    assert!(pair.client.connection().resumed());
    assert!(pair.server.connection().resumed());

    pair.shutdown().unwrap();
}

/// Verifies that an s2n-tls client can use the same session ticket
/// to establish multiple resumed connections to an OpenSSL server.
#[test]
fn s2n_client_reuses_ticket_tls13() {
    required_capability(&[Capability::Tls13], || {
        let (ticket_storage, client_config) = s2n_client_resumption_config(SigType::Rsa2048);

        let server_config = OpenSslConfig::from({
            let mut builder = SslContextBuilder::new_test_config(Mode::Server);
            builder.set_chain(SigType::Rsa2048);
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            builder.build()
        });

        // Initial full handshake to mint the ticket
        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> =
            TlsConnPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();
        pair.round_trip_assert(10_000).unwrap();
        pair.shutdown().unwrap();

        // Extract the ticket
        let ticket = ticket_storage.get_ticket();
        assert!(!ticket.is_empty());

        // Use the same ticket to assert on ticket reusability
        for _ in 0..NUM_RESUMED_RECONNECTS {
            let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> =
                TlsConnPair::from_configs(&client_config, &server_config);

            // Set the same ticket on the s2n connection before handshake
            pair.client
                .connection_mut()
                .set_session_ticket(&ticket)
                .unwrap();

            pair.handshake().unwrap();
            pair.round_trip_assert(10_000).unwrap();

            // Assert resumption happened
            assert!(pair.client.connection().resumed());
            // Assert the ticket was reused
            assert!(pair.server.connection.ssl().session_reused());

            pair.shutdown().unwrap();
        }
    });
}

/// Verifies that an invalid session ticket cannot be used to resume
/// a connection on an s2n-tls server, and that the connection falls back to a full
/// handshake.
#[test]
fn invalid_ticket_falls_back_to_full_handshake() {
    required_capability(&[Capability::Tls13], || {
        // Step 1: OpenSSL client ↔ OpenSSL server handshake to generate a session
        let (openssl_ticket_storage, openssl_client_config) =
            openssl_client_resumption_config(SigType::Rsa2048, SslVersion::TLS1_3);

        let openssl_server_config = OpenSslConfig::from({
            let mut builder = SslContextBuilder::new(SslMethod::tls_server()).unwrap();
            builder.set_chain(SigType::Rsa2048);
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            builder.build()
        });

        // Extract the OpenSSL session from the client
        let openssl_session = {
            let mut openssl_pair: TlsConnPair<OpenSslConnection, OpenSslConnection> =
                TlsConnPair::from_configs(&openssl_client_config, &openssl_server_config);
            openssl_pair.handshake().unwrap();
            openssl_pair.round_trip_assert(10_000).unwrap();
            openssl_pair.shutdown().unwrap();
            openssl_ticket_storage.get_ticket()
        };

        // Create OpenSSL client ↔ s2n server connection
        let s2n_server_config = s2n_server_resumption_config(SigType::Rsa2048);

        // Create a fresh OpenSSL client config for the second connection
        let (_, fresh_openssl_client_config) =
            openssl_client_resumption_config(SigType::Rsa2048, SslVersion::TLS1_3);

        // Install the invalid session into the client and attempt connection
        let resumed = {
            let mut mixed_pair: TlsConnPair<OpenSslConnection, S2NConnection> =
                TlsConnPair::from_configs(&fresh_openssl_client_config, &s2n_server_config);

            unsafe {
                mixed_pair
                    .client
                    .connection
                    .mut_ssl()
                    .set_session(&openssl_session)
                    .unwrap();
            }

            mixed_pair.handshake().unwrap();
            mixed_pair.round_trip_assert(10_000).unwrap();

            // Assert that resumption failed (full handshake occurred)
            let resumed = mixed_pair.server.connection().resumed();
            mixed_pair.shutdown().unwrap();
            resumed
        };

        assert!(!resumed);
    });
}

/// Verifies that a session ticket encrypted under a different STEK
/// falls back to a full handshake.
#[test]
fn mismatched_stek_falls_back_to_full_handshake() {
    required_capability(&[Capability::Tls13], || {
        // Create first s2n server with default STEK
        let server_config_1 = s2n_server_resumption_config(SigType::Rsa2048);

        // Create second s2n server with different STEK
        const DIFFERENT_KEY_VALUE: [u8; 16] = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6];
        let server_config_2 =
            s2n_server_resumption_config_with_key(SigType::Rsa2048, &DIFFERENT_KEY_VALUE);

        // Create OpenSSL client config constrained to TLS 1.3
        let (ticket_storage, client_config) = {
            let session_ticket_storage = OSSLTicketStorage::default();
            let mut builder = SslContextBuilder::new_test_config(Mode::Client);
            builder.set_trust(SigType::Rsa2048);
            builder.set_session_cache_mode(openssl::ssl::SslSessionCacheMode::CLIENT);

            builder.set_new_session_callback({
                let sts = session_ticket_storage.clone();
                move |_, ticket| {
                    let _ = sts.stored_ticket.lock().unwrap().insert(ticket);
                }
            });

            builder
                .set_min_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();

            (session_ticket_storage, builder.build().into())
        };

        // Step 1: Establish session with first server and get ticket
        let ticket = {
            let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
                TlsConnPair::from_configs(&client_config, &server_config_1);
            pair.handshake().unwrap();
            pair.round_trip_assert(10_000).unwrap();

            // Verify this is a full handshake (not resumed)
            assert!(!pair.client.resumed_connection());
            assert!(!pair.server.connection().resumed());

            pair.shutdown().unwrap();
            ticket_storage.get_ticket()
        };

        // Step 2: Try to resume with second server using ticket from first server
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
            TlsConnPair::from_configs(&client_config, &server_config_2);

        // Set the ticket from server 1 on the OpenSSL client
        unsafe {
            pair.client.connection.mut_ssl().set_session(&ticket).unwrap();
        }

        pair.handshake().unwrap();
        pair.round_trip_assert(10_000).unwrap();

        // Verify that resumption failed (full handshake occurred) due to STEK mismatch
        assert!(!pair.client.resumed_connection());
        assert!(!pair.server.connection().resumed());

        pair.shutdown().unwrap();
    });
}
