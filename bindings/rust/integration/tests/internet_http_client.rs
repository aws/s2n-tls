// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Purpose: ensure that s2n-tls is compatible with other http/TLS implementations
///
/// This test uses s2n-tls-hyper to make http requests over a TLS connection to
/// a number of well known http sites.
#[cfg(feature = "network-tests")]
mod http_get {
    use bytes::Bytes;
    use http::{StatusCode, Uri};
    use http_body_util::{BodyExt, Empty};
    use hyper_util::{client::legacy::Client, rt::TokioExecutor};
    use s2n_tls::{config::Config, security};
    use s2n_tls_hyper::connector::HttpsConnector;
    use std::{error::Error, str::FromStr};
    use tracing_subscriber::filter::LevelFilter;

    #[derive(Debug)]
    struct TestCase {
        pub query_target: &'static str,
        pub expected_status_code: u16,
    }

    impl TestCase {
        const fn new(domain: &'static str, expected_status_code: u16) -> Self {
            TestCase {
                query_target: domain,
                expected_status_code,
            }
        }
    }

    const TEST_CASES: &[TestCase] = &[
        // Akamai hangs indefinitely. This is also observed with curl and chrome
        // https://github.com/aws/s2n-tls/issues/4883
        // TestCase::new("https://www.akamai.com/", 200),

        // this is a link to the s2n-tls unit test coverage report, hosted on cloudfront
        TestCase::new("https://dx1inn44oyl7n.cloudfront.net/main/index.html", 200),
        // this is a link to a non-existent S3 item
        TestCase::new("https://notmybucket.s3.amazonaws.com/folder/afile.jpg", 403),
        TestCase::new("https://www.amazon.com", 200),
        TestCase::new("https://www.apple.com", 200),
        TestCase::new("https://www.att.com", 200),
        TestCase::new("https://www.cloudflare.com", 200),
        TestCase::new("https://www.ebay.com", 200),
        TestCase::new("https://www.google.com", 200),
        TestCase::new("https://www.mozilla.org", 200),
        TestCase::new("https://www.netflix.com", 200),
        TestCase::new("https://www.openssl.org", 200),
        TestCase::new("https://www.t-mobile.com", 200),
        TestCase::new("https://www.verizon.com", 200),
        TestCase::new("https://www.wikipedia.org", 200),
        TestCase::new("https://www.yahoo.com", 200),
        TestCase::new("https://www.youtube.com", 200),
        TestCase::new("https://www.github.com", 301),
        TestCase::new("https://www.samsung.com", 301),
        TestCase::new("https://www.twitter.com", 301),
        TestCase::new("https://www.facebook.com", 302),
        TestCase::new("https://www.microsoft.com", 302),
        TestCase::new("https://www.ibm.com", 303),
        TestCase::new("https://www.f5.com", 403),
    ];

    #[tokio::test]
    async fn http_get_test() -> Result<(), Box<dyn std::error::Error>> {
        async fn get(test_case: &TestCase) -> Result<(), Box<dyn Error>> {
            for p in [security::DEFAULT, security::DEFAULT_TLS13] {
                tracing::info!("executing test case {:#?} with {:?}", test_case, p);

                let mut config = Config::builder();
                config.set_security_policy(&p)?;

                let connector = HttpsConnector::new(config.build()?);
                let client: Client<_, Empty<Bytes>> =
                    Client::builder(TokioExecutor::new()).build(connector);

                let uri = Uri::from_str(test_case.query_target)?;
                let response = client.get(uri).await?;

                let expected_status = StatusCode::from_u16(test_case.expected_status_code).unwrap();
                assert_eq!(response.status(), expected_status);

                if expected_status == StatusCode::OK {
                    let body = response.into_body().collect().await?.to_bytes();
                    assert!(!body.is_empty());
                }
            }

            Ok(())
        }

        // enable tracing metrics. hyper/http has extensive logging, so these logs
        // are very useful if failures happen in CI.
        tracing_subscriber::fmt()
            .with_max_level(LevelFilter::TRACE)
            .with_test_writer()
            .init();

        for case in TEST_CASES {
            get(case).await?;
        }

        Ok(())
    }
}
