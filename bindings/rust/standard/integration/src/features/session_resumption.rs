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

/// Verifies that an OpenSSL-issued TLS 1.3 session ticket cannot be used to resume
/// a connection on an s2n-tls server, and that the connection falls back to a full
/// handshake.
///
/// TLS 1.3 session tickets are opaque and only meaningful to the server that issued
/// them. An s2n server will not recognize a ticket issued by an OpenSSL server, so
/// the client’s resumption attempt must result in a full handshake (not resumption).
#[test]
fn tls13_openssl_ticket_does_not_resume_with_s2n_server() {
    required_capability(&[Capability::Tls13], || {
        // Step 1: OpenSSL client ↔ OpenSSL server handshake to generate a session
        let (openssl_ticket_storage, openssl_client_config) =
            openssl_client_resumption_config(SigType::Rsa2048, SslVersion::TLS1_3);

        let openssl_server_config = OpenSslConfig::from({
            let mut builder = SslContextBuilder::new(SslMethod::tls_server()).unwrap();
            builder.set_chain(SigType::Rsa2048);
            builder.set_security_level(0);
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            builder.build()
        });

        // Initial OpenSSL ↔ OpenSSL handshake to generate session ticket
        let mut openssl_pair: TlsConnPair<OpenSslConnection, OpenSslConnection> =
            TlsConnPair::from_configs(&openssl_client_config, &openssl_server_config);
        openssl_pair.handshake().unwrap();
        openssl_pair.round_trip_assert(10_000).unwrap();
        openssl_pair.shutdown().unwrap();

        // Step 2: Extract the OpenSSL session from the client
        let openssl_session = openssl_ticket_storage.get_ticket();

        // Step 3: Create OpenSSL client ↔ s2n server connection
        let s2n_server_config = s2n_server_resumption_config(SigType::Rsa2048);

        // Create a fresh OpenSSL client config for the second connection
        let (_, fresh_openssl_client_config) =
            openssl_client_resumption_config(SigType::Rsa2048, SslVersion::TLS1_3);

        let mut mixed_pair: TlsConnPair<OpenSslConnection, S2NConnection> =
            TlsConnPair::from_configs(&fresh_openssl_client_config, &s2n_server_config);

        // Step 4: Install the OpenSSL session into the client and attempt connection
        unsafe {
            mixed_pair
                .client
                .ssl_mut()
                .set_session(&openssl_session)
                .unwrap();
        }

        mixed_pair.handshake().unwrap();
        mixed_pair.round_trip_assert(10_000).unwrap();

        // Step 5: Assert that resumption failed (full handshake occurred)
        // The s2n server should report no resumption
        assert!(!mixed_pair.server.connection().resumed());

        mixed_pair.shutdown().unwrap();
    });
}

/// Verifies that a TLS 1.3-capable s2n client can resume sessions with a TLS 1.2 server.
#[test]
fn resumption_client_supports_tls13_server_tls12() {
    // Configure s2n client to support up to TLS 1.3 (normal configuration)
    let (ticket_storage, client_config) = s2n_client_resumption_config(SigType::Rsa2048);

    // Configure OpenSSL server with max TLS 1.2
    let server_config = OpenSslConfig::from({
        let mut builder = SslContextBuilder::new(SslMethod::tls_server()).unwrap();
        builder.set_chain(SigType::Rsa2048);
        builder.set_security_level(0);
        // Allow TLS 1.2 and below, but not TLS 1.3
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();
        builder.build()
    });

    // Handshake #1: Initial connection
    let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> =
        TlsConnPair::from_configs(&client_config, &server_config);
    pair.handshake().unwrap();
    pair.round_trip_assert(10_000).unwrap();

    assert!(!pair.server.negotiated_tls13());
    assert!(!pair.client.connection().resumed());
    assert!(!pair.server.resumed_connection());

    pair.shutdown().unwrap();

    // Handshake #2: Resume using the stored session ticket
    let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> =
        TlsConnPair::from_configs(&client_config, &server_config);
    let ticket = ticket_storage.get_ticket();
    assert!(!ticket.is_empty());
    pair.client
        .connection_mut()
        .set_session_ticket(&ticket)
        .unwrap();
    pair.handshake().unwrap();
    pair.round_trip_assert(10_000).unwrap();

    // Assert negotiated version == TLS 1.2 and resumed == true
    assert!(!pair.server.negotiated_tls13());
    assert!(pair.client.connection().resumed());
    assert!(pair.server.resumed_connection());

    pair.shutdown().unwrap();
}

/// Verifies that a TLS 1.3-capable OpenSSL client can resume sessions with an s2n TLS 1.2 server.
#[test]
fn resumption_openssl_client_supports_tls13_s2n_server_tls12() {
    // Configure OpenSSL client to support up to TLS 1.3
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

        builder.set_security_level(0);
        // Allow up to TLS 1.3
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();

        (session_ticket_storage, builder.build().into())
    };

    // Configure s2n server with max TLS 1.2
    let server_config = {
        let mut config = s2n_tls::config::Builder::new_test_config(Mode::Server);
        config
            .set_security_policy(&Policy::from_version("20170210").unwrap()) // TLS 1.2 max policy
            .unwrap();
        config.set_chain(SigType::Rsa2048);
        config.enable_session_tickets(true).unwrap();
        config
            .add_session_ticket_key(
                KEY_NAME.as_bytes(),
                KEY_VALUE.as_slice(),
                SystemTime::UNIX_EPOCH,
            )
            .unwrap();
        config.build().unwrap().into()
    };

    // Handshake #1: Initial connection
    let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
        TlsConnPair::from_configs(&client_config, &server_config);
    pair.handshake().unwrap();
    pair.round_trip_assert(10_000).unwrap();

    assert!(!pair.client.negotiated_tls13());
    assert!(!pair.server.connection().resumed());
    assert!(!pair.client.resumed_connection());

    pair.shutdown().unwrap();

    // Handshake #2: Resume using the stored OpenSSL session
    let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
        TlsConnPair::from_configs(&client_config, &server_config);
    let ticket = ticket_storage.get_ticket();
    unsafe { pair.client.ssl_mut().set_session(&ticket).unwrap() };
    pair.handshake().unwrap();
    pair.round_trip_assert(10_000).unwrap();

    assert!(!pair.client.negotiated_tls13());
    assert!(pair.server.connection().resumed());
    assert!(pair.client.resumed_connection());

    pair.shutdown().unwrap();
}
