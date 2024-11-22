// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{config::Config, enums::Version, security::Policy};
use s2n_tls_tokio::{TlsConnector, TlsStream};
use tokio::net::TcpStream;

/// Perform a TLS handshake with port 443 of `domain`.
///
/// * `domain`: The domain to perform the handshake with
/// * `security_policy`: The security policy to set on the handshaking client.
///
/// Returns an open `TlsStream` if the handshake was successful, otherwise an
/// `Err``.
async fn handshake_with_domain(
    domain: &str,
    security_policy: &str,
) -> Result<TlsStream<TcpStream>, Box<dyn std::error::Error>> {
    tracing::info!("querying {domain} with {security_policy}");
    const PORT: u16 = 443;

    let mut config = Config::builder();
    config.set_security_policy(&Policy::from_version(security_policy)?)?;

    let client = TlsConnector::new(config.build()?);
    // open the TCP stream
    let stream = TcpStream::connect((domain, PORT)).await?;
    // complete the TLS handshake
    Ok(client.connect(domain, stream).await?)
}

#[cfg(feature = "pq")]
mod kms_pq {
    use super::*;

    const DOMAIN: &str = "kms.us-east-1.amazonaws.com";

    // confirm that we successfully negotiate a supported PQ key exchange.
    //
    // Note: In the future KMS will deprecate kyber_r3 in favor of ML-KEM.
    // At that point this test should be updated with a security policy that
    // supports ML-KEM.
    #[test_log::test(tokio::test)]
    async fn pq_handshake() -> Result<(), Box<dyn std::error::Error>> {
        let tls = handshake_with_domain(DOMAIN, "KMS-PQ-TLS-1-0-2020-07").await?;

        assert_eq!(
            tls.as_ref().cipher_suite()?,
            "ECDHE-KYBER-RSA-AES256-GCM-SHA384"
        );
        assert_eq!(tls.as_ref().kem_name(), Some("kyber512r3"));

        Ok(())
    }

    // We want to confirm that non-supported kyber drafts successfully fall
    // back to a full handshake.
    #[test_log::test(tokio::test)]
    async fn early_draft_falls_back_to_classical() -> Result<(), Box<dyn std::error::Error>> {
        const EARLY_DRAFT_PQ_POLICIES: &[&str] = &[
            "KMS-PQ-TLS-1-0-2019-06",
            "PQ-SIKE-TEST-TLS-1-0-2019-11",
            "KMS-PQ-TLS-1-0-2020-02",
            "PQ-SIKE-TEST-TLS-1-0-2020-02",
        ];

        for security_policy in EARLY_DRAFT_PQ_POLICIES {
            let tls = handshake_with_domain(DOMAIN, security_policy).await?;

            assert_eq!(tls.as_ref().cipher_suite()?, "ECDHE-RSA-AES256-GCM-SHA384");
            assert_eq!(tls.as_ref().kem_name(), None);
        }
        Ok(())
    }
}

#[test_log::test(tokio::test)]
async fn tls_client() -> Result<(), Box<dyn std::error::Error>> {
    const DOMAINS: &[&str] = &[
        // The akamai request should be in internet_https_client.rs but Akamai
        // http requests hang indefinitely. This behavior is also observed with
        // curl and chrome. https://github.com/aws/s2n-tls/issues/4883
        "www.akamai.com",
        // microsoft.com started returning 403 HTTP status codes in CI, but returned 200 locally.
        // This domain may be throttling HTTP requests from CI, so a plain TLS connection is tested
        // instead.
        "www.microsoft.com",
    ];

    for domain in DOMAINS {
        tracing::info!("querying {domain}");

        let tls12 = handshake_with_domain(domain, "default").await?;
        assert_eq!(tls12.as_ref().actual_protocol_version()?, Version::TLS12);

        let tls13 = handshake_with_domain(domain, "default_tls13").await?;
        assert_eq!(tls13.as_ref().actual_protocol_version()?, Version::TLS13);
    }

    Ok(())
}
