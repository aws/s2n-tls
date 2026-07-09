// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls_metrics_schema::static_lists::{ClientIssue, Signature, Version};

use crate::{parsing::ClientHelloSupportedParameters, record::NegotiatedParameters};

pub fn has_issue(
    issue: ClientIssue,
    negotiated: &NegotiatedParameters,
    supported: &ClientHelloSupportedParameters,
) -> bool {
    match issue {
        ClientIssue::Tls13WithoutS2NSupportedGroups => {
            let supports_tls13 = supported.supported_versions().contains(&Version::TLS_1_3);
            // Check whether any of the client's offered groups are ones that
            // s2n-tls actually supports. In the wild we have seen clients that
            // only support FFDHE groups
            let no_s2n_groups = supported.supported_groups().is_some_and(|groups| {
                !groups.iter().any(|g| g.available_in_s2n())
            });
            supports_tls13 && no_s2n_groups
        }
        ClientIssue::Tls13WithoutModernSigAlgs => {
            let supports_tls13 = supported.supported_versions().contains(&Version::TLS_1_3);
            let only_legacy = {
                match supported.supported_signatures() {
                    None => {
                        // the client didn't send signature algorithms, which
                        // is required for TLS 1.3
                        false
                    }
                    Some(sigs) => {
                        let mut only_legacy = true;

                        for sig in sigs {
                            let legacy = Signature::SIG_ALGS_TLS13_UNSUPPORTED.contains(sig);
                            if !legacy {
                                only_legacy = false;
                                break;
                            }
                        }
                        only_legacy
                    }
                }
            };
            supports_tls13 && only_legacy
        }
        ClientIssue::Tls13WithoutSupportedGroup => {
            let supports_tls13 = supported.supported_versions().contains(&Version::TLS_1_3);
            let no_supported_groups_extension = supported.supported_groups().is_none();
            supports_tls13 && no_supported_groups_extension
        }
        ClientIssue::LiedAboutSupportedSignatures => {
            supported.supported_signatures().is_some_and(|signatures| {
                negotiated
                    .signature
                    .is_some_and(|negotiated| !signatures.contains(&negotiated))
            })
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use s2n_tls_metrics_schema::static_lists::{Cipher, Group};
    use s2n_codec::zerocopy::U16;

    /// An FFDHE group that s2n-tls does not support for TLS 1.3.
    /// ffdhe2048 = IANA value 0x0100
    const FFDHE2048: Group = Group(U16::new(0x0100));

    /// Helper to construct a NegotiatedParameters for testing.
    fn negotiated(signature: Option<Signature>) -> NegotiatedParameters {
        NegotiatedParameters {
            version: Version::TLS_1_3,
            cipher: Cipher::TLS_AES_128_GCM_SHA256,
            group: Some(Group::x25519),
            signature,
        }
    }

    /// Helper to construct a ClientHelloSupportedParameters for testing.
    fn supported(
        versions: Vec<Version>,
        groups: Option<Vec<Group>>,
        signatures: Option<Vec<Signature>>,
    ) -> ClientHelloSupportedParameters {
        ClientHelloSupportedParameters::from_parts(
            versions,
            vec![Cipher::TLS_AES_128_GCM_SHA256],
            groups,
            signatures,
        )
    }

    #[test]
    fn tls13_without_s2n_supported_groups() {
        let issue = ClientIssue::Tls13WithoutS2NSupportedGroups;
        let neg = negotiated(None);

        // positive: TLS 1.3 with only FFDHE groups (not supported by s2n-tls)
        let sup = supported(
            vec![Version::TLS_1_3, Version::TLS_1_2],
            Some(vec![FFDHE2048]),
            Some(vec![Signature::ecdsa_secp256r1_sha256]),
        );
        assert!(has_issue(issue, &neg, &sup));

        // positive: TLS 1.3 with extension present but empty
        let sup = supported(
            vec![Version::TLS_1_3, Version::TLS_1_2],
            Some(vec![]),
            Some(vec![Signature::ecdsa_secp256r1_sha256]),
        );
        assert!(has_issue(issue, &neg, &sup));

        // negative: has at least one recognized group
        let sup = supported(
            vec![Version::TLS_1_3],
            Some(vec![FFDHE2048, Group::x25519]),
            Some(vec![Signature::ecdsa_secp256r1_sha256]),
        );
        assert!(!has_issue(issue, &neg, &sup));

        // negative: no TLS 1.3 support, so empty groups don't matter
        let sup = supported(
            vec![Version::TLS_1_2],
            Some(vec![]),
            Some(vec![Signature::rsa_pkcs1_sha256]),
        );
        assert!(!has_issue(issue, &neg, &sup));
    }

    #[test]
    fn tls13_without_modern_sig_algs() {
        let issue = ClientIssue::Tls13WithoutModernSigAlgs;
        let neg = negotiated(None);

        // positive: TLS 1.3 with only legacy sig algs
        let sup = supported(
            vec![Version::TLS_1_3],
            Some(vec![Group::x25519]),
            Some(vec![
                Signature::rsa_pkcs1_sha256,
                Signature::rsa_pkcs1_sha384,
            ]),
        );
        assert!(has_issue(issue, &neg, &sup));

        // negative: includes at least one modern sig alg
        let sup = supported(
            vec![Version::TLS_1_3],
            Some(vec![Group::x25519]),
            Some(vec![
                Signature::rsa_pkcs1_sha256,
                Signature::ecdsa_secp256r1_sha256,
            ]),
        );
        assert!(!has_issue(issue, &neg, &sup));

        // negative: no signature_algorithms extension (absence != legacy-only)
        let sup = supported(vec![Version::TLS_1_3], Some(vec![Group::x25519]), None);
        assert!(!has_issue(issue, &neg, &sup));
    }

    #[test]
    fn tls13_without_supported_group() {
        let issue = ClientIssue::Tls13WithoutSupportedGroup;
        let neg = negotiated(None);

        // positive: TLS 1.3 with no supported_groups extension
        let sup = supported(
            vec![Version::TLS_1_3],
            None,
            Some(vec![Signature::ecdsa_secp256r1_sha256]),
        );
        assert!(has_issue(issue, &neg, &sup));

        // negative: no TLS 1.3 support, missing extension is irrelevant
        let sup = supported(
            vec![Version::TLS_1_2],
            None,
            Some(vec![Signature::rsa_pkcs1_sha256]),
        );
        assert!(!has_issue(issue, &neg, &sup));
    }

    #[test]
    fn lied_about_supported_signatures() {
        let issue = ClientIssue::LiedAboutSupportedSignatures;

        // positive: negotiated sig is not in the client's advertised list
        let neg = negotiated(Some(Signature::rsa_pss_rsae_sha256));
        let sup = supported(
            vec![Version::TLS_1_3],
            Some(vec![Group::x25519]),
            Some(vec![
                Signature::ecdsa_secp256r1_sha256,
                Signature::ecdsa_secp384r1_sha384,
            ]),
        );
        assert!(has_issue(issue, &neg, &sup));

        // negative: negotiated sig IS in the advertised list
        let neg = negotiated(Some(Signature::ecdsa_secp256r1_sha256));
        let sup = supported(
            vec![Version::TLS_1_3],
            Some(vec![Group::x25519]),
            Some(vec![
                Signature::ecdsa_secp256r1_sha256,
                Signature::rsa_pss_rsae_sha256,
            ]),
        );
        assert!(!has_issue(issue, &neg, &sup));

        // negative: no signature was negotiated
        let neg = negotiated(None);
        let sup = supported(
            vec![Version::TLS_1_3],
            Some(vec![Group::x25519]),
            Some(vec![Signature::ecdsa_secp256r1_sha256]),
        );
        assert!(!has_issue(issue, &neg, &sup));
    }
}
