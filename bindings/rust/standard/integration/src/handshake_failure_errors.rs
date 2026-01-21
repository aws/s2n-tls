// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use brass_aphid_wire_decryption::decryption::key_manager::KeyManager;
use brass_aphid_wire_messages::{
    iana::{self},
    protocol::{
        content_value::{ContentValue, HandshakeMessageValue},
        AlertDescription, AlertLevel,
    },
};
use openssl::ssl::{SslContextBuilder, SslVersion};
use s2n_tls::{error::ErrorType, security::Policy};
use tls_harness::{
    cohort::{OpenSslConnection, S2NConnection},
    harness::TlsConfigBuilderPair,
    TlsConnPair,
};

use crate::capability_check::{required_capability, Capability};

#[test]
fn no_protocols_in_common() {
    required_capability(&[Capability::Tls13], || {
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let tls13_only_policy = Policy::from_version("20250414").unwrap();
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            configs
                .server
                .set_security_policy(&tls13_only_policy)
                .unwrap();
            configs
                .client
                .set_max_proto_version(Some(SslVersion::TLS1_2))
                .unwrap();

            configs.connection_pair()
        };

        let error = pair.handshake().unwrap_err();
        let s2n_error: Box<s2n_tls::error::Error> = error.downcast().unwrap();
        assert_eq!(s2n_error.kind(), ErrorType::ProtocolError);
        assert_eq!(s2n_error.name(), "S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED");
        assert_eq!(
            s2n_error.message(),
            "TLS protocol version is not supported by configuration"
        );
    });
}

#[test]
fn no_ciphers_in_common() {
    required_capability(&[Capability::Tls13], || {
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let tls13_only_policy = Policy::from_version("20250414").unwrap();
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            configs
                .server
                .set_security_policy(&tls13_only_policy)
                .unwrap();
            configs
                .client
                .set_ciphersuites("TLS_SHA256_SHA256")
                .unwrap();

            configs.connection_pair()
        };

        let error = pair.handshake().unwrap_err();
        let s2n_error: Box<s2n_tls::error::Error> = error.downcast().unwrap();
        assert_eq!(s2n_error.kind(), ErrorType::ProtocolError);
        assert_eq!(s2n_error.name(), "S2N_ERR_CIPHER_NOT_SUPPORTED");
        assert_eq!(s2n_error.message(), "Cipher is not supported");
    })
}

#[test]
fn no_groups_in_common() {
    required_capability(&[Capability::Tls13], || {
        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let tls13_only_policy = Policy::from_version("20250414").unwrap();
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            configs
                .server
                .set_security_policy(&tls13_only_policy)
                .unwrap();
            configs.client.set_groups_list("x448").unwrap();

            configs.connection_pair()
        };

        let error = pair.handshake().unwrap_err();
        let s2n_error: Box<s2n_tls::error::Error> = error.downcast().unwrap();
        assert_eq!(s2n_error.kind(), ErrorType::InternalError);
        assert_eq!(s2n_error.name(), "S2N_ERR_INVALID_SUPPORTED_GROUP_STATE");
        assert_eq!(s2n_error.message(), "SupportedGroup preference decision entered invalid state and selected both KEM and EC Curve");
    })
}

/// When there are no signature schemes in common, s2n-tls will make a "best effort"
/// to proceed with the handshake anyways. This means that s2n-tls won't actually
/// fail the connection, and instead it will show up as an alert from the peer.
#[test]
fn no_signatures_in_common() {
    required_capability(&[Capability::Tls13], || {
        let key_manager = KeyManager::new();

        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            // "20250211" doesn't allow any SHA256 signatures
            let sha384_only_policy = Policy::from_version("20250211").unwrap();
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();
            configs
                .server
                .set_security_policy(&sha384_only_policy)
                .unwrap();
            key_manager.enable_s2n_logging(&mut configs.server);
            configs
                .client
                .set_sigalgs_list("rsa_pss_pss_sha256")
                .unwrap();

            configs.connection_pair()
        };
        pair.io.enable_decryption(key_manager);

        let error = pair.handshake().unwrap_err();
        let ossl_error: Box<openssl::ssl::Error> = error.downcast().unwrap();
        // the client/openssl fails when checking the signature, because s2n-tls sent
        // a signature that it did not advertise support for
        // Error {
        // code: ErrorCode(1),
        // cause: Some(Ssl(ErrorStack([
        //      Error {
        //          code: 167772530,
        //          library: "SSL routines",
        //          function: "tls12_check_peer_sigalg",
        //          reason: "wrong signature type",
        //          file: "ssl/t1_lib.c",
        //          line: 2797 }
        // ]))) }
        assert!(ossl_error.to_string().contains("tls12_check_peer_sigalg"));
        assert!(ossl_error.to_string().contains("wrong signature type"));

        let transcript = pair.io.decrypter.borrow().as_ref().unwrap().transcript();
        let content = transcript.content_transcript.lock().unwrap().clone();

        // confirm that s2n-tls sent an unexpected signature.
        {
            let certificate_verify = content
                .iter()
                .filter_map(|(_sender, content_value)| match content_value {
                    ContentValue::Handshake(HandshakeMessageValue::CertVerifyTls13(
                        cert_verify,
                    )) => Some(cert_verify),
                    _ => None,
                })
                .next()
                .unwrap();
            // s2n-tls send a certificate verify with rsa_pss_rsae_sha384, which is not
            // one of the client's supported signature algorithms
            assert_eq!(
                certificate_verify.algorithm,
                iana::constants::rsa_pss_rsae_sha384
            );
        }

        // confirm that the client sent an alert indicating its displeasure
        {
            let alert = content
                .iter()
                .filter(|(sender, _content)| {
                    *sender == brass_aphid_wire_decryption::decryption::Mode::Client
                })
                .filter_map(|(_sender, content_value)| match content_value {
                    ContentValue::Alert(alert) => Some(alert),
                    _ => None,
                })
                .next()
                .unwrap();
            assert_eq!(alert.level, AlertLevel::Fatal);
            assert_eq!(alert.description, AlertDescription::HandshakeFailure)
        }
    })
}
