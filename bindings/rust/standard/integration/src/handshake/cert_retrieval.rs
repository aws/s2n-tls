// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests that a TLS endpoint can retrieve its peer's certificate chain and its
//! own (selected) certificate chain after both successful and failed handshakes.

use s2n_tls::{config::Builder, enums::ClientAuthType, error::Error as S2NError};
use tls_harness::{
    cohort::{s2n_tls::HostNameHandler, S2NConfig, S2NConnection},
    harness::read_to_bytes,
    PemType, SigType, TlsConnPair,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build an s2n-tls config suitable for a server that presents a certificate
/// and optionally requires client auth.
fn server_config(client_auth: bool, trust_peer: bool) -> Builder {
    let sig = SigType::Rsa2048;

    let mut builder = Builder::new();
    builder.with_system_certs(false).unwrap();
    builder
        .load_pem(
            &read_to_bytes(PemType::ServerCertChain, sig),
            &read_to_bytes(PemType::ServerKey, sig),
        )
        .unwrap();
    if client_auth {
        builder
            .set_client_auth_type(ClientAuthType::Required)
            .unwrap();

        if trust_peer {
            builder
                .trust_pem(&read_to_bytes(PemType::CACert, sig))
                .unwrap();
        }
    }
    builder
        .set_verify_host_callback(HostNameHandler::new("localhost"))
        .unwrap();
    builder
}

/// Build an s2n-tls config suitable for a client that trusts the test CA and
/// optionally presents a client certificate.
fn client_config(present_client_cert: bool, trust_peer: bool) -> Builder {
    let sig = SigType::Rsa2048;

    let mut builder = Builder::new();
    builder.with_system_certs(false).unwrap();
    if trust_peer {
        builder
            .trust_pem(&read_to_bytes(PemType::CACert, sig))
            .unwrap();
    }
    if present_client_cert {
        builder
            .load_pem(
                &read_to_bytes(PemType::ClientCertChain, sig),
                &read_to_bytes(PemType::ClientKey, sig),
            )
            .unwrap();
    }
    builder
        .set_verify_host_callback(HostNameHandler::new("localhost"))
        .unwrap();
    builder
}

/// Assert that a certificate chain is non-empty and every certificate has
/// non-empty DER data.
fn assert_chain_valid(chain: &s2n_tls::cert_chain::CertificateChain) {
    assert!(!chain.is_empty(), "certificate chain should not be empty");
    for cert in chain.iter() {
        let cert = cert.expect("cert iteration should succeed");
        let der = cert.der().expect("DER encoding should succeed");
        assert!(!der.is_empty(), "certificate DER should not be empty");
    }
}

// ============================================================================
// Successful handshake – server auth only
// ============================================================================

#[test]
fn successful_server_auth() {
    let server_cfg: S2NConfig = server_config(false, true).build().unwrap().into();
    let client_cfg: S2NConfig = client_config(false, true).build().unwrap().into();

    let mut pair =
        TlsConnPair::<S2NConnection, S2NConnection>::from_configs(&client_cfg, &server_cfg);
    pair.handshake().unwrap();

    // The client should see the server's certificate as its peer.
    let client_peer = pair.client.connection().peer_cert_chain().unwrap();
    assert_chain_valid(&client_peer);

    // The server selected its own certificate to present.
    let server_own = pair.server.connection().selected_cert().unwrap();
    assert_chain_valid(&server_own);

    // Cross-check: the client's peer cert should match the server's own cert.
    let client_peer_cert = client_peer.iter().next().unwrap().unwrap();
    let client_peer_der = client_peer_cert.der().unwrap();
    let server_own_cert = server_own.iter().next().unwrap().unwrap();
    let server_own_der = server_own_cert.der().unwrap();
    assert_eq!(client_peer_der, server_own_der);
}

// ============================================================================
// Successful handshake – mutual TLS (client auth)
// ============================================================================

#[test]
fn successful_client_auth() {
    let server_cfg: S2NConfig = server_config(true, true).build().unwrap().into();
    let client_cfg: S2NConfig = client_config(true, true).build().unwrap().into();

    let mut pair =
        TlsConnPair::<S2NConnection, S2NConnection>::from_configs(&client_cfg, &server_cfg);
    pair.handshake().unwrap();

    let client_own = pair.client.connection().selected_cert().unwrap();
    assert_chain_valid(&client_own);

    let server_peer = pair.server.connection().peer_cert_chain().unwrap();
    assert_chain_valid(&server_peer);

    // Cross-check: the server's peer cert should match the client's own cert.
    let server_peer_cert = server_peer.iter().next().unwrap().unwrap();
    let server_peer_der = server_peer_cert.der().unwrap();
    let client_own_cert = client_own.iter().next().unwrap().unwrap();
    let client_own_der = client_own_cert.der().unwrap();
    assert_eq!(server_peer_der, client_own_der);
}

// ============================================================================
// Failed handshake – server auth rejected by client
// ============================================================================

#[test]
fn failed_server_auth() {
    let server_cfg: S2NConfig = server_config(false, true).build().unwrap().into();

    // Client does not trust server cert
    let client_cfg: S2NConfig = client_config(false, false).build().unwrap().into();

    let mut pair =
        TlsConnPair::<S2NConnection, S2NConnection>::from_configs(&client_cfg, &server_cfg);

    let err = pair.handshake().unwrap_err();
    // The error should be a protocol error from the cert validation rejection.
    let s2n_err: Box<S2NError> = err.downcast().unwrap();
    assert_eq!(s2n_err.kind(), s2n_tls::error::ErrorType::ProtocolError);

    // The server selected its own certificate to present.
    let server_own = pair.server.connection().selected_cert().unwrap();
    assert_chain_valid(&server_own);

    // Client cannot retrieve peer's unvalidated cert.
    assert!(pair.client.connection().peer_cert_chain().is_err());
}

// ============================================================================
// Failed handshake – client auth rejected by server
// ============================================================================

#[test]
fn failed_client_auth() {
    // Server does not trust client cert.
    let server_cfg: S2NConfig = server_config(true, false).build().unwrap().into();
    let client_cfg: S2NConfig = client_config(true, true).build().unwrap().into();

    let mut pair =
        TlsConnPair::<S2NConnection, S2NConnection>::from_configs(&client_cfg, &server_cfg);

    let err = pair.handshake().unwrap_err();
    let s2n_err: Box<S2NError> = err.downcast().unwrap();
    assert_eq!(s2n_err.kind(), s2n_tls::error::ErrorType::ProtocolError);

    // After a failed handshake the client still selected its own cert to send.
    let client_own = pair.client.connection().selected_cert();
    assert!(client_own.is_some());
    assert_chain_valid(&client_own.unwrap());

    // Server cannot retrieve peer's unvalidated cert.
    assert!(pair
        .server
        .connection()
        .client_cert_chain_bytes()
        .unwrap()
        .is_none());
    assert!(pair.server.connection().peer_cert_chain().is_err());
}
