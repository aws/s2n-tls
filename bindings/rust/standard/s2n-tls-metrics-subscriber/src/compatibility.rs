// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This module holds utilities for checking when a client is compatible with some
//! particular TLS Profile.

use crate::parsing::ClientHelloSupportedParameters;
use s2n_tls_metrics_schema::static_lists::{CertKeyType, Cipher, Group, Signature, Version};

pub(crate) trait TlsProfile {
    const ALLOWED_VERSIONS: &[Version];
    const ALLOWED_CIPHERS: &[Cipher];
    const ALLOWED_GROUPS: &[Group];
    const ALLOWED_SIGNATURES: &[Signature];

    /// The certificate key types the policy permits in a *locally presented*
    /// certificate chain.
    ///
    /// `None` means the policy imposes no certificate-key restriction (its
    /// underlying s2n security policy has no `certificate_key_preferences`, or
    /// does not apply them locally), so any certificate is acceptable.
    ///
    /// `Some(list)` means the policy validates local certificates against
    /// `certificate_key_preferences` (i.e. `certificate_preferences_apply_locally`
    /// is set). A handshake is only compatible if *every* observed local cert
    /// key is in `list`, because a single incompatible certificate breaks the
    /// handshake under the real policy.
    const ALLOWED_CERT_KEYS: Option<&[CertKeyType]>;

    /// returns true if a peer could handshake with this [`TlsProfile`], given
    /// the parameters advertised in its `ClientHello` and the key types of the
    /// certificate chain this endpoint presents locally.
    ///
    /// `local_cert_keys` are the [`CertKeyType`]s parsed from the local
    /// (selected) certificate chain. This is required in addition to the
    /// ClientHello parameters because policies like CNSA1 reject certificates
    /// whose key is not in `certificate_key_preferences` (e.g. a P-256 cert
    /// under a P-384-only policy), which the advertised parameters alone cannot
    /// reveal.
    fn supported(
        client_hello: &ClientHelloSupportedParameters,
        local_cert_keys: &[CertKeyType],
    ) -> bool {
        let supported_version = client_hello
            .supported_versions()
            .iter()
            .any(|client_version| Self::ALLOWED_VERSIONS.contains(client_version));

        let supported_cipher = client_hello
            .supported_ciphers()
            .iter()
            .any(|client_cipher| Self::ALLOWED_CIPHERS.contains(client_cipher));

        let supported_signature = client_hello
            .supported_signatures()
            .map(|client_signatures| {
                client_signatures
                    .iter()
                    .any(|client_signature| Self::ALLOWED_SIGNATURES.contains(client_signature))
            })
            .unwrap_or(false);

        let supported_group = client_hello
            .supported_groups()
            .map(|client_groups| {
                client_groups
                    .iter()
                    .any(|client_group| Self::ALLOWED_GROUPS.contains(client_group))
            })
            .unwrap_or(false);

        let supported_cert = match Self::ALLOWED_CERT_KEYS {
            // No certificate-key restriction: the cert dimension always passes.
            None => true,
            // The policy restricts cert keys, but we couldn't observe any local
            // cert key (no local cert, or a parse failure). We cannot prove the
            // migration is safe, so fail closed.
            Some(_) if local_cert_keys.is_empty() => false,
            // Every local cert key must be allowed: a single incompatible cert
            // would be rejected by the real policy and break the handshake.
            Some(allowed) => local_cert_keys
                .iter()
                .all(|cert_key| allowed.contains(cert_key)),
        };

        supported_version
            && supported_cipher
            && supported_group
            && supported_signature
            && supported_cert
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

    // The `default` policy has no `certificate_key_preferences`, so it imposes
    // no restriction on the local certificate's key type.
    const ALLOWED_CERT_KEYS: Option<&[CertKeyType]> = None;
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

    // The `default_fips` policy has `certificate_signature_preferences` but no
    // `certificate_key_preferences`, and does not apply certificate preferences
    // locally, so it imposes no restriction on the local certificate's key type.
    const ALLOWED_CERT_KEYS: Option<&[CertKeyType]> = None;
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

    // CNSA1 applies certificate preferences locally and only permits the key
    // types in `s2n_certificate_key_preferences_20250429`: P-384 and RSA
    // (rsae/pss) 3072/4096. In particular a P-256 certificate is rejected and
    // would break the handshake, so it must not be counted as compatible.
    const ALLOWED_CERT_KEYS: Option<&[CertKeyType]> = Some(&[
        CertKeyType::Secp384r1,
        CertKeyType::Rsa3072,
        CertKeyType::Rsa4096,
        CertKeyType::RsaPss3072,
        CertKeyType::RsaPss4096,
    ]);
}

pub(crate) struct Cnsa2;
impl TlsProfile for Cnsa2 {
    const ALLOWED_VERSIONS: &[Version] = &[Version::TLS_1_3];

    const ALLOWED_CIPHERS: &[Cipher] = &[Cipher::TLS_AES_256_GCM_SHA384];

    const ALLOWED_GROUPS: &[Group] = &[Group::MLKEM1024];

    const ALLOWED_SIGNATURES: &[Signature] = &[Signature::mldsa87];

    // CNSA2 permits only ML-DSA-87 certificates. The metrics cert parser does
    // not yet recognize ML-DSA keys (they parse to `CertKeyType::Unknown`), so
    // encoding a `Some([...])` restriction here would incorrectly reject a valid
    // ML-DSA-87 cert. We leave the cert dimension unrestricted for now; CNSA2 is
    // already tightly bounded by its `mldsa87` signature and `MLKEM1024` group
    // requirements, which no classical (P-256/P-384/RSA) peer satisfies.
    //
    // TODO: add per-cert CNSA2 gating once the cert parser learns ML-DSA (would
    // require an `MlDsa87` `CertKeyType` variant + OID mapping).
    const ALLOWED_CERT_KEYS: Option<&[CertKeyType]> = None;
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

    /// Extract the key types of the connection's local (selected) certificate
    /// chain, mirroring how `record.rs` feeds `local_cert_keys` into the
    /// compatibility check. On the server side of these tests `selected_cert()`
    /// is the server's own chain.
    fn local_cert_keys(conn: &s2n_tls::connection::Connection) -> Vec<CertKeyType> {
        let mut keys = Vec::new();
        if let Some(chain) = conn.selected_cert() {
            for cert in chain.iter().flatten() {
                if let Ok(der) = cert.der() {
                    if let Ok(parsed) = crate::parsing::cert::parse(der) {
                        keys.push(parsed.key_type);
                    }
                }
            }
        }
        keys
    }

    /// Build `ClientHelloSupportedParameters` that satisfy CNSA1's non-certificate
    /// dimensions (TLS 1.2/1.3, AES-256-GCM-SHA384, secp384r1,
    /// ecdsa_secp384r1_sha384) so tests can isolate the certificate dimension.
    fn cnsa1_compatible_client_hello() -> ClientHelloSupportedParameters {
        ClientHelloSupportedParameters::from_parts(
            vec![Version::TLS_1_2, Version::TLS_1_3],
            vec![Cipher::TLS_AES_256_GCM_SHA384],
            Some(vec![Group::secp384r1]),
            Some(vec![Signature::ecdsa_secp384r1_sha384]),
        )
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

    fn ecdsa_p256_cert() -> CertKeyPair {
        CertKeyPair::from_path(
            "permutations/ec_ecdsa_p256_sha256/",
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
            &ClientHelloSupportedParameters::new(ch).unwrap(),
            &local_cert_keys(&server),
        ));
    }

    #[test]
    fn default_fips_compatible_with_fips() {
        let server = handshake_with_policy("default_fips", &default_cert());
        let ch = server.client_hello().unwrap();
        assert!(Fips20251201::supported(
            &ClientHelloSupportedParameters::new(ch).unwrap(),
            &local_cert_keys(&server),
        ));
    }

    #[test]
    fn cnsa_1_compatible_with_cnsa1() {
        let server = handshake_with_policy("cnsa_1", &ecdsa_p384_cert());
        let ch = server.client_hello().unwrap();
        assert!(Cnsa1::supported(
            &ClientHelloSupportedParameters::new(ch).unwrap(),
            &local_cert_keys(&server),
        ));
    }

    #[test]
    fn cnsa_2_compatible_with_cnsa2() {
        let (client_config, server_config) = mldsa87_configs("cnsa_2");
        let mut pair = TestPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();
        let ch = pair.server.client_hello().unwrap();
        let supported_parameters = ClientHelloSupportedParameters::new(ch).unwrap();
        let cert_keys = local_cert_keys(&pair.server);

        assert!(Cnsa2::supported(&supported_parameters, &cert_keys));
        // doesn't support required groups/signatures
        assert!(!Cnsa1::supported(&supported_parameters, &cert_keys));
        // doesn't support required groups
        assert!(!Fips20251201::supported(&supported_parameters, &cert_keys));
        // doesn't support required groups
        assert!(!General20251201::supported(
            &supported_parameters,
            &cert_keys
        ));
    }

    #[test]
    fn cnsa_1_2_interop_compatible_with_cnsa1_and_cnsa2() {
        // cnsa_1_2_interop should be compatible with both Cnsa1 and Cnsa2 profiles
        let cert = ecdsa_p384_cert();
        let server = handshake_with_policy("cnsa_1_2_interop", &cert);
        let ch = server.client_hello().unwrap();
        let supported_parameters = ClientHelloSupportedParameters::new(ch).unwrap();
        let cert_keys = local_cert_keys(&server);
        assert!(Cnsa1::supported(&supported_parameters, &cert_keys));
        assert!(Cnsa2::supported(&supported_parameters, &cert_keys));
    }

    /// Regression test for issue #5982: a peer whose ClientHello satisfies all
    /// of CNSA1's advertised requirements is NOT CNSA1-compatible when the
    /// local certificate uses a P-256 key, because the real CNSA1 policy rejects
    /// P-256 certificates.
    #[test]
    fn cnsa1_incompatible_with_p256_cert() {
        let params = cnsa1_compatible_client_hello();
        // sanity: the ClientHello parameters alone satisfy CNSA1 when the cert
        // key is compatible.
        assert!(Cnsa1::supported(&params, &[CertKeyType::Secp384r1]));
        // but a P-256 cert must disqualify CNSA1 compatibility.
        assert!(!Cnsa1::supported(&params, &[CertKeyType::Secp256r1]));
    }

    /// A P-384 local certificate keeps a CNSA1-satisfying ClientHello compatible.
    #[test]
    fn cnsa1_compatible_with_p384_cert() {
        let params = cnsa1_compatible_client_hello();
        assert!(Cnsa1::supported(&params, &[CertKeyType::Secp384r1]));
    }

    /// CNSA1 also permits RSA-3072/4096 certificates, but not RSA-2048 or P-256.
    #[test]
    fn cnsa1_cert_key_allow_list() {
        let params = cnsa1_compatible_client_hello();
        assert!(Cnsa1::supported(&params, &[CertKeyType::Rsa3072]));
        assert!(Cnsa1::supported(&params, &[CertKeyType::Rsa4096]));
        assert!(Cnsa1::supported(&params, &[CertKeyType::RsaPss3072]));
        assert!(!Cnsa1::supported(&params, &[CertKeyType::Rsa2048]));
        assert!(!Cnsa1::supported(&params, &[CertKeyType::Rsa1024]));
    }

    /// A single incompatible cert anywhere in the local chain disqualifies
    /// compatibility, because the real policy validates every cert it presents.
    #[test]
    fn cnsa1_incompatible_when_any_chain_cert_incompatible() {
        let params = cnsa1_compatible_client_hello();
        // leaf P-384 (ok) but an intermediate is P-256 (not ok)
        assert!(!Cnsa1::supported(
            &params,
            &[CertKeyType::Secp384r1, CertKeyType::Secp256r1],
        ));
    }

    /// When the cert is a policy-restricted profile (CNSA1) but no local cert
    /// key could be observed, we fail closed (cannot prove migration is safe).
    #[test]
    fn cnsa1_incompatible_when_no_local_cert() {
        let params = cnsa1_compatible_client_hello();
        assert!(!Cnsa1::supported(&params, &[]));
    }

    /// Profiles with no certificate-key restriction (General/Fips) are
    /// unaffected by the local cert key types, including when none are observed.
    #[test]
    fn unrestricted_profiles_ignore_cert_keys() {
        // General/Fips advertised requirements satisfied by a broad ClientHello.
        let params = ClientHelloSupportedParameters::from_parts(
            vec![Version::TLS_1_2, Version::TLS_1_3],
            vec![Cipher::TLS_AES_128_GCM_SHA256],
            Some(vec![Group::secp256r1]),
            Some(vec![Signature::ecdsa_secp256r1_sha256]),
        );
        // A P-256 cert (or no cert at all) is fine for the unrestricted profiles.
        assert!(General20251201::supported(
            &params,
            &[CertKeyType::Secp256r1]
        ));
        assert!(General20251201::supported(&params, &[]));
        assert!(Fips20251201::supported(&params, &[CertKeyType::Secp256r1]));
        assert!(Fips20251201::supported(&params, &[]));
    }

    /// End-to-end analogue of the regression test using a real handshake: a
    /// P-256 server cert must not be counted CNSA1-compatible, while a P-384
    /// server cert is. The client uses a permissive policy so the handshake
    /// succeeds regardless (we are measuring the profile, not enforcing it).
    #[test]
    fn cnsa1_p256_vs_p384_end_to_end() {
        let p256_server = handshake_with_policy("test_all", &ecdsa_p256_cert());
        let p256_ch = p256_server.client_hello().unwrap();
        let p256_params = ClientHelloSupportedParameters::new(p256_ch).unwrap();
        assert!(!Cnsa1::supported(
            &p256_params,
            &local_cert_keys(&p256_server),
        ));

        let p384_server = handshake_with_policy("cnsa_1", &ecdsa_p384_cert());
        let p384_ch = p384_server.client_hello().unwrap();
        let p384_params = ClientHelloSupportedParameters::new(p384_ch).unwrap();
        assert!(Cnsa1::supported(
            &p384_params,
            &local_cert_keys(&p384_server),
        ));
    }
}
