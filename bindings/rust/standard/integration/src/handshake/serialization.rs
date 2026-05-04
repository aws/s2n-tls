// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::capability_check::{required_capability, Capability};
use openssl::ssl::{SslContextBuilder, SslVersion};
use s2n_tls::{enums::SerializationVersion, security::Policy};
use tls_harness::{
    cohort::{OpenSslConnection, S2NConnection},
    harness::{TlsConfigBuilder, TlsConnection},
    Mode, SigType, TlsConnPair,
};

#[derive(Debug)]
struct TestCase {
    version: SslVersion,
    cipher: &'static str,
}

impl TestCase {
    fn is_tls13(&self) -> bool {
        self.version == SslVersion::TLS1_3
    }
}

/// Test Cases are designed to cover
/// 1. protocol versions
/// 2. different kinds of ciphers
///
/// Internally, serialized connections have to rehydrate the secrets and record
/// protocol, so we want test coverage over the different ways that secrets and
/// the record protocol may need hydration. To that end we have coverage over
/// - CBC ciphers: block cipher with MAC
/// - GCM ciphers: block cipher with AAD
/// - CHACHA ciphers: stream cipher
/// As well as the different protocol versions.
const TEST_CASES: &[TestCase] = &[
    TestCase {
        version: SslVersion::TLS1,
        cipher: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    },
    TestCase {
        version: SslVersion::TLS1_1,
        cipher: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    },
    TestCase {
        version: SslVersion::TLS1_2,
        cipher: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    },
    TestCase {
        version: SslVersion::TLS1_2,
        cipher: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    },
    TestCase {
        version: SslVersion::TLS1_2,
        cipher: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    },
    TestCase {
        version: SslVersion::TLS1_3,
        cipher: "TLS_AES_128_GCM_SHA256",
    },
    TestCase {
        version: SslVersion::TLS1_3,
        cipher: "TLS_CHACHA20_POLY1305_SHA256",
    },
];

fn build_openssl_client_config(case: &TestCase) -> openssl::ssl::SslContext {
    let mut builder = SslContextBuilder::new_test_config(Mode::Client);
    builder.set_trust(SigType::Rsa2048);
    builder.set_min_proto_version(Some(case.version)).unwrap();
    builder.set_max_proto_version(Some(case.version)).unwrap();
    if case.is_tls13() {
        builder.set_ciphersuites(case.cipher).unwrap();
    } else {
        builder.set_cipher_list(case.cipher).unwrap();
    }
    builder.build()
}

fn build_s2n_server_config() -> s2n_tls::config::Config {
    let mut builder = s2n_tls::config::Builder::new_test_config(Mode::Server);
    builder.set_chain(SigType::Rsa2048);
    builder
        .set_security_policy(&Policy::from_version("test_all").unwrap())
        .unwrap()
        .set_serialization_version(SerializationVersion::V1)
        .unwrap();
    builder.build().unwrap()
}

/// Performs the full serialize → deserialize → round-trip flow.
/// Returns Ok(()) on success, Err on any failure.
fn run_serialization_test(case: &TestCase) -> Result<(), Box<dyn std::error::Error>> {
    let client_config = build_openssl_client_config(case).into();
    let server_config: tls_harness::cohort::s2n_tls::S2NConfig = build_s2n_server_config().into();

    // Handshake and do a preliminary round trip
    let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> =
        TlsConnPair::from_configs(&client_config, &server_config);
    pair.handshake()?;
    pair.round_trip_assert(10_000)?;

    // Serialize the server connection
    let conn = pair.server.connection();
    let length = conn.serialization_length()?;
    let mut buf = vec![0u8; length];
    conn.serialize(&mut buf)?;

    // Create a new server connection and deserialize into it
    let mut new_server = S2NConnection::new_from_config(Mode::Server, &server_config, &pair.io)?;
    new_server.connection_mut().deserialize(&buf)?;
    pair.server = new_server;

    // Verify the deserialized server can still exchange data
    pair.round_trip_assert(10_000)?;

    Ok(())
}

#[test]
fn tls13_serialization() {
    required_capability(&[Capability::Tls13], || {
        for case in TEST_CASES.iter().filter(|c| c.is_tls13()) {
            run_serialization_test(case).unwrap();
        }
    });
}

#[test]
fn serialization() {
    for case in TEST_CASES.iter().filter(|c| !c.is_tls13()) {
        let result = run_serialization_test(case);
        // TODO: TLS 1.0 serialization is not currently supported.
        // https://github.com/aws/s2n-tls/issues/5538
        // Remove this special case once it is fixed.
        if case.version == SslVersion::TLS1 {
            assert!(result.is_err());
        } else {
            assert!(result.is_ok(), "{case:?} failed");
        }
    }
}
