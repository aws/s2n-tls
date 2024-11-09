// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{config::Config, security::Policy};
use s2n_tls_tokio::TlsConnector;
use std::error::Error;
use tokio::net::TcpStream;
use tracing::level_filters::LevelFilter;

#[derive(Debug)]
struct TestCase {
    s2n_security_policy: &'static str,
    expected_cipher: &'static str,
    expected_kem: Option<&'static str>,
}

// When KMS moves to standardized ML-KEM, this test will fail. The test should
// then be updated with the new security policy that supports ML-KEM.
const TEST_CASES: &[TestCase] = &[
    // positive case: negotiates kyber
    TestCase {
        s2n_security_policy: "KMS-PQ-TLS-1-0-2020-07",
        expected_cipher: "ECDHE-KYBER-RSA-AES256-GCM-SHA384",
        expected_kem: Some("kyber512r3"),
    },
    // negative cases: these policies support a variety of early kyber drafts.
    // We want to confirm that non-supported kyber drafts successfully fall
    // back to a full handshake.
    TestCase {
        s2n_security_policy: "KMS-PQ-TLS-1-0-2019-06",
        expected_cipher: "ECDHE-RSA-AES256-GCM-SHA384",
        expected_kem: None,
    },
    TestCase {
        s2n_security_policy: "PQ-SIKE-TEST-TLS-1-0-2019-11",
        expected_cipher: "ECDHE-RSA-AES256-GCM-SHA384",
        expected_kem: None,
    },
    TestCase {
        s2n_security_policy: "KMS-PQ-TLS-1-0-2020-02",
        expected_cipher: "ECDHE-RSA-AES256-GCM-SHA384",
        expected_kem: None,
    },
    TestCase {
        s2n_security_policy: "PQ-SIKE-TEST-TLS-1-0-2020-02",
        expected_cipher: "ECDHE-RSA-AES256-GCM-SHA384",
        expected_kem: None,
    },
];

/// Purpose: ensure that we remain compatible with existing pq AWS deployments.
///
/// This test makes network calls over the public internet.
///
/// KMS is has PQ support. Assert that we successfully negotiate PQ key exchange.
#[tokio::test]
async fn pq_kms_test() -> Result<(), Box<dyn Error>> {
    const DOMAIN: &str = "kms.us-east-1.amazonaws.com";
    const SOCKET_ADDR: (&str, u16) = (DOMAIN, 443);

    async fn test(test_case: &TestCase) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!("executing test case: {:#?}", test_case);

        let mut config = Config::builder();
        config.set_security_policy(&Policy::from_version(test_case.s2n_security_policy)?)?;

        let client = TlsConnector::new(config.build()?);
        // open the TCP stream
        let stream = TcpStream::connect(SOCKET_ADDR).await?;
        // complete the TLS handshake
        let tls = client.connect(DOMAIN, stream).await?;

        assert_eq!(tls.as_ref().cipher_suite()?, test_case.expected_cipher);
        assert_eq!(tls.as_ref().kem_name()?, test_case.expected_kem);

        Ok(())
    }

    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::TRACE)
        .with_test_writer()
        .init();

    for test_case in TEST_CASES {
        test(test_case).await?
    }

    Ok(())
}
