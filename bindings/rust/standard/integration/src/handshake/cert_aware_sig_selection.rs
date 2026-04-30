// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! TLS 1.3 Signature Negotiation changes rather significantly from TLS 1.2
//!
//! In TLS 1.2, a client would indicate support for e.g. ECDSA+SHA256 & ECDSA+SHA384.
//! These support any ECDSA cert.
//!
//! In TLS 1.3, a client indicates support for a specific scheme like `ecdsa_secp256r1_sha256`
//! or `ecdsa_secp384r1_sha384`. A server can only choose that scheme if it's ECDSA
//! cert matches the curve specified in the signature scheme.
//!
//! s2n-tls previously has a bug in this selection logic (https://github.com/aws/s2n-tls/pull/5713).
//! This test protects against regressions in that behavior.

use crate::{
    capability_check::{required_capability, Capability},
    utilities::certs::{self, CertMaterials},
};
use brass_aphid_wire_decryption::decryption::{key_manager::KeyManager, Mode};
use brass_aphid_wire_messages::{
    iana::{self, SignatureScheme},
    protocol::content_value::{ContentValue, HandshakeMessageValue},
};
use openssl::ssl::SslContextBuilder;
use s2n_tls::security::{Policy, DEFAULT_PQ};
use tls_harness::{
    cohort::{OpenSslConnection, S2NConnection},
    harness::TlsConfigBuilderPair,
    TlsConnPair,
};

/// Handshake `server_policy` with `cert_materials`, and return the SignatureScheme
/// from the server's CertVerify message.
fn trial(server_policy: &Policy, cert_materials: &CertMaterials) -> SignatureScheme {
    let key_manager = KeyManager::new();

    let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
        let mut configs =
            TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
        // Setup OpenSSL client
        configs.client.set_ca_file(&cert_materials.ca_path).unwrap();

        configs.server.set_security_policy(server_policy).unwrap();
        configs.server.set_max_blinding_delay(0).unwrap();
        configs
            .server
            .load_pem(&cert_materials.server_chain(), &cert_materials.server_key())
            .unwrap();
        key_manager.enable_s2n_logging(&mut configs.server);

        configs.connection_pair()
    };
    pair.io.enable_decryption(key_manager.clone());

    pair.handshake().unwrap();
    pair.shutdown().unwrap();

    let cert_verify = {
        let transcript = pair.io.decrypter.borrow().as_ref().unwrap().transcript();
        let transcript = transcript.content_transcript.lock().unwrap().clone();
        transcript
            .into_iter()
            .find_map(|(sender, message)| {
                if let ContentValue::Handshake(HandshakeMessageValue::CertVerifyTls13(verify)) =
                    message
                {
                    assert_eq!(sender, Mode::Server);
                    Some(verify)
                } else {
                    None
                }
            })
            .unwrap()
    };
    cert_verify.algorithm
}

/// We use the same security policy and client configuration, forcing s2n-tls to
/// go through its own server preference list and correctly skip signatures incompatible
/// with its certificate
#[test]
fn signature_selection() {
    // ECDSA
    required_capability(&[Capability::Tls13], || {
        let secp256r1 = CertMaterials::from_permutation("ec_ecdsa_p256_sha256");
        let secp521r1 = CertMaterials::from_permutation("ec_ecdsa_p521_sha512");

        // arbitrary policy which supports TLS 1.3 and ECDSA
        let policy = Policy::from_version("20240503").unwrap();

        assert_eq!(
            trial(&policy, &secp256r1),
            iana::constants::ecdsa_secp256r1_sha256
        );
        assert_eq!(
            trial(&policy, &secp521r1),
            iana::constants::ecdsa_secp521r1_sha512
        );
    });

    // MLDSA
    required_capability(&[Capability::MLDsa], || {
        assert_eq!(
            trial(&DEFAULT_PQ, &certs::ML_DSA_87),
            iana::constants::mldsa87
        );
        assert_eq!(
            trial(&DEFAULT_PQ, &certs::ML_DSA_44),
            iana::constants::mldsa44
        );
    });
}
