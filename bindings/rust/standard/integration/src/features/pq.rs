// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::capability_check::{required_capability, Capability};
use openssl::ssl::SslContextBuilder;
use s2n_tls::{enums::SignatureAlgorithm, security::{Policy, DEFAULT_PQ}};
use std::fs;
use tls_harness::{
    cohort::{s2n_tls::HostNameHandler, OpenSslConnection, S2NConnection},
    harness::TlsConfigBuilderPair,
    TlsConnPair,
};

const TEST_PEMS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../tests/pems/");

#[test]
fn s2n_mldsa_client() {
    required_capability(&[Capability::MLDsa], || {
        let cert_path = format!("{TEST_PEMS_PATH}mldsa/ML-DSA-87.crt");
        let key_path = format!("{TEST_PEMS_PATH}mldsa/ML-DSA-87-seed.priv");

        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = {
            let mut configs =
                TlsConfigBuilderPair::<s2n_tls::config::Builder, SslContextBuilder>::default();

            // Setup s2n-tls client with default_pq
            configs.client.set_security_policy(&DEFAULT_PQ).unwrap();
            configs.client.set_max_blinding_delay(0).unwrap();

            // This test uses the RFC ML-DSA certificate ("LAMPS WG").
            // In the DEFAULT_PQ / MLDSA path the expected hostname
            // is "LAMPS WG", so we install a host-verify callback that
            // accepts that value.
            configs
                .client
                .set_verify_host_callback(HostNameHandler {
                    expected_server_name: "LAMPS WG",
                })
                .unwrap();
            let cert = fs::read(&cert_path).unwrap();
            configs.client.trust_pem(&cert).unwrap();

            // Setup OpenSSL server with ML-DSA certs
            configs
                .server
                .set_private_key_file(&key_path, openssl::ssl::SslFiletype::PEM)
                .unwrap();
            configs
                .server
                .set_certificate_chain_file(&cert_path)
                .unwrap();

            configs.connection_pair()
        };

        pair.handshake().unwrap();

        let conn = pair.client.connection();
        assert_eq!(
            conn.selected_signature_algorithm().unwrap(),
            SignatureAlgorithm::MLDSA
        );
    });
}

#[test]
fn s2n_mldsa_server() {
    required_capability(&[Capability::MLDsa], || {
        let cert_path = format!("{TEST_PEMS_PATH}mldsa/ML-DSA-87.crt");
        let key_path = format!("{TEST_PEMS_PATH}mldsa/ML-DSA-87-seed.priv");

        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();

            // Setup OpenSSL client
            configs.client.set_ca_file(&cert_path).unwrap();

            // Setup s2n-tls server with ML-DSA certs
            configs.server.set_security_policy(&DEFAULT_PQ).unwrap();
            configs.server.set_max_blinding_delay(0).unwrap();
            let cert = fs::read(&cert_path).unwrap();
            let key = fs::read(&key_path).unwrap();
            configs.server.load_pem(&cert, &key).unwrap();

            configs.connection_pair()
        };

        pair.handshake().unwrap();

        let conn = pair.server.connection();
        assert_eq!(
            conn.selected_signature_algorithm().unwrap(),
            SignatureAlgorithm::MLDSA
        );
    });
}

#[test]
fn s2n_mlkem_client() {
    required_capability(&[Capability::MLKem], || {
        let cert_path =
            format!("{TEST_PEMS_PATH}permutations/ec_ecdsa_p256_sha384/server-chain.pem");
        let key_path = format!("{TEST_PEMS_PATH}permutations/ec_ecdsa_p256_sha384/server-key.pem");

        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = {
            let mut configs =
                TlsConfigBuilderPair::<s2n_tls::config::Builder, SslContextBuilder>::default();

            // Setup s2n-tls client with default_pq
            configs.client.set_security_policy(&DEFAULT_PQ).unwrap();
            configs.client.set_max_blinding_delay(0).unwrap();
            let cert = fs::read(&cert_path).unwrap();
            configs.client.trust_pem(&cert).unwrap();

            // Setup OpenSSL server restricted to SecP384r1MLKEM1024
            configs
                .server
                .set_private_key_file(&key_path, openssl::ssl::SslFiletype::PEM)
                .unwrap();
            configs
                .server
                .set_certificate_chain_file(&cert_path)
                .unwrap();
            configs
                .server
                .set_groups_list("SecP384r1MLKEM1024")
                .unwrap();

            configs.connection_pair()
        };

        pair.handshake().unwrap();

        let conn = pair.client.connection();
        let kem_group = conn.kem_group_name().unwrap();
        assert_eq!(kem_group, "SecP384r1MLKEM1024");
    });
}

#[test]
fn s2n_mlkem_server() {
    required_capability(&[Capability::MLKem], || {
        let cert_path =
            format!("{TEST_PEMS_PATH}permutations/ec_ecdsa_p256_sha384/server-chain.pem");
        let key_path = format!("{TEST_PEMS_PATH}permutations/ec_ecdsa_p256_sha384/server-key.pem");

        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();

            // Setup OpenSSL client restricted to SecP384r1MLKEM1024
            configs.client.set_ca_file(&cert_path).unwrap();
            configs
                .client
                .set_groups_list("SecP384r1MLKEM1024")
                .unwrap();

            // Setup s2n-tls server
            configs.server.set_security_policy(&DEFAULT_PQ).unwrap();
            configs.server.set_max_blinding_delay(0).unwrap();
            let cert = fs::read(&cert_path).unwrap();
            let key = fs::read(&key_path).unwrap();
            configs.server.load_pem(&cert, &key).unwrap();

            configs.connection_pair()
        };

        pair.handshake().unwrap();

        let conn = pair.server.connection();
        let kem_group = conn.kem_group_name().unwrap();
        assert_eq!(kem_group, "SecP384r1MLKEM1024");
    });
}

// Client-side test only exercises MLKEM key exchange; trusting the leaf cert avoids ML-DSA verification.
#[test]
fn s2n_pure_mlkem_client() {
    required_capability(&[Capability::MLKem], || {
        let cert_path = format!("{TEST_PEMS_PATH}mldsa/ML-DSA-87.crt");
        let key_path = format!("{TEST_PEMS_PATH}mldsa/ML-DSA-87-seed.priv");

        let mut pair: TlsConnPair<S2NConnection, OpenSslConnection> = {
            let mut configs =
                TlsConfigBuilderPair::<s2n_tls::config::Builder, SslContextBuilder>::default();

            // Setup s2n-tls client with test_all
            let test_all_policy = Policy::from_version("test_all").unwrap();
            configs
                .client
                .set_security_policy(&test_all_policy)
                .unwrap();
            configs.client.set_max_blinding_delay(0).unwrap();
            let cert = fs::read(&cert_path).unwrap();
            configs.client.trust_pem(&cert).unwrap();

            // Setup OpenSSL server restricted to MLKEM1024
            configs
                .server
                .set_private_key_file(&key_path, openssl::ssl::SslFiletype::PEM)
                .unwrap();
            configs
                .server
                .set_certificate_chain_file(&cert_path)
                .unwrap();
            configs.server.set_groups_list("MLKEM1024").unwrap();

            configs.connection_pair()
        };

        pair.handshake().unwrap();

        let conn = pair.client.connection();
        let kem_group = conn.kem_group_name().unwrap();
        assert_eq!(kem_group, "MLKEM1024");
    });
}

// Server-side test exercises MLKEM plus ML-DSA, since the server must sign CertificateVerify with an ML-DSA key.
#[test]
fn s2n_pure_mlkem_server() {
    required_capability(&[Capability::MLKem, Capability::MLDsa], || {
        let cert_path = format!("{TEST_PEMS_PATH}mldsa/ML-DSA-87.crt");
        let key_path = format!("{TEST_PEMS_PATH}mldsa/ML-DSA-87-seed.priv");

        let mut pair: TlsConnPair<OpenSslConnection, S2NConnection> = {
            let mut configs =
                TlsConfigBuilderPair::<SslContextBuilder, s2n_tls::config::Builder>::default();

            // Setup OpenSSL client restricted to MLKEM1024
            configs.client.set_ca_file(&cert_path).unwrap();
            configs.client.set_groups_list("MLKEM1024").unwrap();

            // Setup s2n-tls server with test_all
            let test_all_policy = Policy::from_version("test_all").unwrap();
            configs
                .server
                .set_security_policy(&test_all_policy)
                .unwrap();
            configs.server.set_max_blinding_delay(0).unwrap();
            let cert = fs::read(&cert_path).unwrap();
            let key = fs::read(&key_path).unwrap();
            configs.server.load_pem(&cert, &key).unwrap();

            configs.connection_pair()
        };

        pair.handshake().unwrap();

        let conn = pair.server.connection();
        let kem_group = conn.kem_group_name().unwrap();
        assert_eq!(kem_group, "MLKEM1024");
    });
}
