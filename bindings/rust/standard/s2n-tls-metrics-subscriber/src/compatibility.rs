// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This module holds utilities for checking when a client is compatible with some
//! particular TLS Profile.

use crate::{
    parsing::ClientHelloSupportedParameters,
    static_lists::{Cipher, Group, Signature, Version},
};

pub(crate) trait TlsProfile {
    const ALLOWED_VERSIONS: &[Version];
    const ALLOWED_CIPHERS: &[Cipher];
    const ALLOWED_GROUPS: &[Group];
    const ALLOWED_SIGNATURES: &[Signature];

    /// returns true if a client could handshake with this [`TlsProfile`]
    fn supported(client_hello: &ClientHelloSupportedParameters) -> bool {
        let supported_version = client_hello
            .supported_versions()
            .map(|client_versions| {
                client_versions
                    .iter()
                    .any(|client_version| Self::ALLOWED_VERSIONS.contains(client_version))
            })
            .unwrap_or(false);

        let supported_cipher = client_hello
            .supported_ciphers()
            .map(|client_ciphers| {
                client_ciphers
                    .iter()
                    .any(|client_cipher| Self::ALLOWED_CIPHERS.contains(client_cipher))
            })
            .unwrap_or(false);

        let supported_signature = client_hello
            .supported_signatures()
            .ok()
            .flatten()
            .map(|client_signatures| {
                client_signatures
                    .iter()
                    .any(|client_signature| Self::ALLOWED_SIGNATURES.contains(client_signature))
            })
            .unwrap_or(false);

        let supported_group = client_hello
            .supported_groups()
            .ok()
            .flatten()
            .map(|client_groups| {
                client_groups
                    .iter()
                    .any(|client_group| Self::ALLOWED_GROUPS.contains(client_group))
            })
            .unwrap_or(false);

        supported_version && supported_cipher && supported_group && supported_signature
    }
}

pub(crate) struct General20251201;
impl TlsProfile for General20251201 {
    const ALLOWED_VERSIONS: &[Version] = &[Version::TLS_1_2, Version::TLS_1_3];

    const ALLOWED_CIPHERS: &[Cipher] = &[
        Cipher::TLS_AES_128_GCM_SHA256,
        Cipher::TLS_AES_256_GCM_SHA384,
        Cipher::TLS_CHACHA20_POLY1305_SHA256,
        Cipher::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        Cipher::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        Cipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        Cipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        // omission of TLS 1.2 CHACHA ciphers is deliberate, because they
        // aren't supported in ELB security policies.
    ];

    const ALLOWED_GROUPS: &[Group] = &[
        Group::x25519,
        Group::secp256r1,
        Group::secp384r1,
        Group::secp521r1,
        Group::X25519MLKEM768,
        Group::SecP256r1MLKEM768,
        Group::SecP384r1MLKEM1024,
    ];

    const ALLOWED_SIGNATURES: &[Signature] = &[
        Signature::rsa_pss_pss_sha256,
        Signature::rsa_pss_pss_sha384,
        Signature::rsa_pss_pss_sha512,
        Signature::rsa_pss_rsae_sha256,
        Signature::rsa_pss_rsae_sha384,
        Signature::rsa_pss_rsae_sha512,
        Signature::ecdsa_secp256r1_sha256,
        Signature::ecdsa_secp384r1_sha384,
        Signature::ecdsa_secp521r1_sha512,
    ];
}

pub(crate) struct Fips20251201;
impl TlsProfile for Fips20251201 {
    const ALLOWED_VERSIONS: &[Version] = &[Version::TLS_1_2, Version::TLS_1_3];

    const ALLOWED_CIPHERS: &[Cipher] = &[
        Cipher::TLS_AES_128_GCM_SHA256,
        Cipher::TLS_AES_256_GCM_SHA384,
        Cipher::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        Cipher::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        Cipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        Cipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ];

    const ALLOWED_GROUPS: &[Group] = &[
        Group::secp256r1,
        Group::secp384r1,
        Group::secp521r1,
        Group::X25519MLKEM768,
        Group::SecP256r1MLKEM768,
        Group::SecP384r1MLKEM1024,
    ];

    const ALLOWED_SIGNATURES: &[Signature] = &[
        Signature::rsa_pss_pss_sha256,
        Signature::rsa_pss_pss_sha384,
        Signature::rsa_pss_pss_sha512,
        Signature::rsa_pss_rsae_sha256,
        Signature::rsa_pss_rsae_sha384,
        Signature::rsa_pss_rsae_sha512,
        Signature::ecdsa_secp256r1_sha256,
        Signature::ecdsa_secp384r1_sha384,
        Signature::ecdsa_secp521r1_sha512,
    ];
}

pub(crate) struct Cnsa1;
impl TlsProfile for Cnsa1 {
    const ALLOWED_VERSIONS: &[Version] = &[Version::TLS_1_2, Version::TLS_1_3];

    const ALLOWED_CIPHERS: &[Cipher] = &[
        Cipher::TLS_AES_256_GCM_SHA384,
        Cipher::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    ];

    const ALLOWED_GROUPS: &[Group] = &[Group::secp384r1];

    const ALLOWED_SIGNATURES: &[Signature] = &[Signature::ecdsa_secp384r1_sha384];
}

pub(crate) struct Cnsa2;
impl TlsProfile for Cnsa2 {
    const ALLOWED_VERSIONS: &[Version] = &[Version::TLS_1_3];

    const ALLOWED_CIPHERS: &[Cipher] = &[Cipher::TLS_AES_256_GCM_SHA384];

    const ALLOWED_GROUPS: &[Group] = &[Group::MLKEM1024];

    const ALLOWED_SIGNATURES: &[Signature] = &[Signature::mldsa87];
}

#[cfg(test)]
mod tests {
    use super::*;
    use s2n_tls::{
        config::Builder,
        security::Policy,
        testing::{CertKeyPair, InsecureAcceptAllCertificatesHandler, TestPair},
    };

    /// Build a TestPair where the client uses `policy_name` and the server uses
    /// a permissive policy with certs compatible with the client policy.
    /// Returns the server connection (which holds the parsed client hello).
    fn handshake_with_policy(
        policy_name: &str,
        cert: &CertKeyPair,
    ) -> s2n_tls::connection::Connection {
        let policy = Policy::from_version(policy_name).unwrap();

        // client config: just the policy + trust
        let client_config = {
            let mut b = Builder::new();
            b.set_security_policy(&policy).unwrap();
            b.with_system_certs(false).unwrap();
            b.trust_pem(cert.ca_cert()).unwrap();
            b.set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
                .unwrap();
            b.build().unwrap()
        };

        // server config: permissive policy so it can always accept, with matching certs
        let server_config = {
            let mut b = Builder::new();
            b.set_security_policy(&Policy::from_version("test_all").unwrap())
                .unwrap();
            b.with_system_certs(false).unwrap();
            b.load_pem(cert.cert(), cert.key()).unwrap();
            b.trust_pem(cert.ca_cert()).unwrap();
            b.set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
                .unwrap();
            b.build().unwrap()
        };

        let mut pair = TestPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();
        pair.server
    }

    fn default_cert() -> CertKeyPair {
        CertKeyPair::default()
    }

    fn ecdsa_p384_cert() -> CertKeyPair {
        CertKeyPair::from_path(
            "permutations/ec_ecdsa_p384_sha384/",
            "server-chain",
            "server-key",
            "ca-cert",
        )
    }

    /// ML-DSA files don't use .pem extension, so we build configs directly
    /// instead of using CertKeyPair.
    fn mldsa87_configs(policy_name: &str) -> (s2n_tls::config::Config, s2n_tls::config::Config) {
        let pems = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../tests/pems/mldsa/");
        let cert = std::fs::read(format!("{pems}ML-DSA-87.crt")).unwrap();
        let key = std::fs::read(format!("{pems}ML-DSA-87-seed.priv")).unwrap();

        let client_config = {
            let mut b = Builder::new();
            b.set_security_policy(&Policy::from_version(policy_name).unwrap())
                .unwrap();
            b.with_system_certs(false).unwrap();
            b.trust_pem(&cert).unwrap();
            b.set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
                .unwrap();
            b.build().unwrap()
        };
        let server_config = {
            let mut b = Builder::new();
            b.set_security_policy(&Policy::from_version("test_all").unwrap())
                .unwrap();
            b.with_system_certs(false).unwrap();
            b.load_pem(&cert, &key).unwrap();
            b.trust_pem(&cert).unwrap();
            b.set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
                .unwrap();
            b.build().unwrap()
        };
        (client_config, server_config)
    }

    #[test]
    fn default_compatible_with_general() {
        let server = handshake_with_policy("default", &default_cert());
        let ch = server.client_hello().unwrap();
        assert!(General20251201::supported(
            &ClientHelloSupportedParameters::new(ch)
        ));
    }

    #[test]
    fn default_fips_compatible_with_fips() {
        let server = handshake_with_policy("default_fips", &default_cert());
        let ch = server.client_hello().unwrap();
        assert!(Fips20251201::supported(
            &ClientHelloSupportedParameters::new(ch)
        ));
    }

    #[test]
    fn cnsa_1_compatible_with_cnsa1() {
        let server = handshake_with_policy("cnsa_1", &ecdsa_p384_cert());
        let ch = server.client_hello().unwrap();
        assert!(Cnsa1::supported(&ClientHelloSupportedParameters::new(ch)));
    }

    #[test]
    fn cnsa_2_compatible_with_cnsa2() {
        let (client_config, server_config) = mldsa87_configs("cnsa_2");
        let mut pair = TestPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();
        let ch = pair.server.client_hello().unwrap();
        let supported_parameters = ClientHelloSupportedParameters::new(ch);

        assert!(Cnsa2::supported(&supported_parameters));
        // doesn't support required groups/signatures
        assert!(!Cnsa1::supported(&supported_parameters));
        // doesn't support required groups
        assert!(!Fips20251201::supported(&supported_parameters));
        // doesn't support required groups
        assert!(!General20251201::supported(&supported_parameters));
    }

    #[test]
    fn cnsa_1_2_interop_compatible_with_cnsa1_and_cnsa2() {
        // cnsa_1_2_interop should be compatible with both Cnsa1 and Cnsa2 profiles
        let cert = ecdsa_p384_cert();
        let server = handshake_with_policy("cnsa_1_2_interop", &cert);
        let ch = server.client_hello().unwrap();
        let supported_parameters = ClientHelloSupportedParameters::new(ch);
        assert!(Cnsa1::supported(&supported_parameters));
        assert!(Cnsa2::supported(&supported_parameters));
    }
}
