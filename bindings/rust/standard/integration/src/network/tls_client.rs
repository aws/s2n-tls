// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{
    config::Config,
    enums::Version,
    security::{self, Policy},
};
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
    security_policy: &Policy,
) -> Result<TlsStream<TcpStream>, Box<dyn std::error::Error>> {
    tracing::info!("querying {domain} with {:?}", security_policy);
    const PORT: u16 = 443;

    let mut config = Config::builder();
    config.set_security_policy(security_policy)?;

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
        let policy = Policy::from_version("PQ-TLS-1-2-2023-10-09")?;
        let tls = handshake_with_domain(DOMAIN, &policy).await?;

        assert_eq!(
            tls.as_ref().cipher_suite()?,
            "TLS_AES_256_GCM_SHA384"
        );
        assert_eq!(tls.as_ref().kem_group_name(), Some("x25519_kyber-512-r3"));

        Ok(())
    }
}

#[test_log::test(tokio::test)]
async fn tls_client() -> Result<(), Box<dyn std::error::Error>> {
    // The akamai request should be in internet_https_client.rs but Akamai
    // http requests hang indefinitely. This behavior is also observed with
    // curl and chrome. https://github.com/aws/s2n-tls/issues/4883
    const DOMAINS: &[&str] = &["www.akamai.com"];

    for domain in DOMAINS {
        tracing::info!("querying {domain}");

        let tls12 = handshake_with_domain(domain, &security::TESTING_TLS12).await?;
        assert_eq!(tls12.as_ref().actual_protocol_version()?, Version::TLS12);

        let tls13 = handshake_with_domain(domain, &security::DEFAULT_TLS13).await?;
        assert_eq!(tls13.as_ref().actual_protocol_version()?, Version::TLS13);
    }

    Ok(())
}
