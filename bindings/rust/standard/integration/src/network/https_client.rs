// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bytes::Bytes;
use http::{Response, StatusCode, Uri};
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use s2n_tls::{
    config::Config,
    security::{self, Policy},
};
use s2n_tls_hyper::connector::HttpsConnector;
use std::str::FromStr;

#[derive(Debug)]
struct TestCase {
    pub query_target: &'static str,
    /// We accept multiple possible results because some websites frequently change
    /// behavior, possibly as a result of throttling the IP ranges of our CI
    /// providers.
    pub expected_status_codes: &'static [u16],
}

impl TestCase {
    const fn new(domain: &'static str, expected_status_codes: &'static [u16]) -> Self {
        TestCase {
            query_target: domain,
            expected_status_codes,
        }
    }
}

const TEST_CASES: &[TestCase] = &[
    // this is a link to the s2n-tls unit test coverage report, hosted on cloudfront
    TestCase::new(
        "https://dx1inn44oyl7n.cloudfront.net/main/index.html",
        &[200],
    ),
    // this is a link to a non-existent S3 item
    TestCase::new(
        "https://notmybucket.s3.amazonaws.com/folder/afile.jpg",
        &[403],
    ),
    TestCase::new("https://www.amazon.com", &[200]),
    TestCase::new("https://www.apple.com", &[200]),
    TestCase::new("https://www.att.com", &[200]),
    TestCase::new("https://www.cloudflare.com", &[200]),
    TestCase::new("https://www.ebay.com", &[200]),
    TestCase::new("https://www.google.com", &[200]),
    TestCase::new("https://www.mozilla.org", &[200]),
    TestCase::new("https://www.netflix.com", &[200]),
    TestCase::new("https://www.openssl.org", &[200]),
    TestCase::new("https://www.t-mobile.com", &[200]),
    TestCase::new("https://www.verizon.com", &[200]),
    TestCase::new("https://www.wikipedia.org", &[200]),
    TestCase::new("https://www.yahoo.com", &[200]),
    TestCase::new("https://www.youtube.com", &[200]),
    TestCase::new("https://www.github.com", &[301]),
    TestCase::new("https://www.samsung.com", &[301]),
    TestCase::new("https://www.twitter.com", &[301]),
    TestCase::new("https://www.facebook.com", &[302]),
    // 2024-11-21: Microsoft had been consistently returning a 302. It then started
    // returning 403 codes in CI, but was returning 200 codes when run locally.
    TestCase::new("https://www.microsoft.com", &[200, 302, 403]),
    TestCase::new("https://www.ibm.com", &[303]),
    TestCase::new("https://www.f5.com", &[403]),
];

/// perform an HTTP GET request against `uri` using an s2n-tls config with
/// `security_policy`.
async fn https_get(
    uri: &str,
    security_policy: &Policy,
) -> Result<Response<Incoming>, hyper_util::client::legacy::Error> {
    let mut config = Config::builder();
    config.set_security_policy(security_policy).unwrap();

    let connector = HttpsConnector::new(config.build().unwrap());
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(connector);

    let uri = Uri::from_str(uri).unwrap();
    client.get(uri).await
}

/// Ensure that s2n-tls is compatible with other http/TLS implementations.
///
/// This test uses s2n-tls-hyper to make http requests over a TLS connection to
/// a number of well known http sites.
#[test_log::test(tokio::test)]
async fn http_get_test() -> Result<(), Box<dyn std::error::Error>> {
    for test_case in TEST_CASES {
        for policy in [security::DEFAULT, security::DEFAULT_TLS13] {
            tracing::info!("executing test case {:#?} with {:?}", test_case, policy);

            let response = https_get(test_case.query_target, &policy).await?;
            let status_code = response.status().as_u16();

            let status_was_expected = test_case.expected_status_codes.contains(&status_code);
            if !status_was_expected {
                tracing::error!("unexpected status code: {status_code}");
            }
            assert!(status_was_expected);

            if status_code == StatusCode::OK.as_u16() {
                let body = response.into_body().collect().await?.to_bytes();
                assert!(!body.is_empty());
            }
        }
    }

    Ok(())
}
