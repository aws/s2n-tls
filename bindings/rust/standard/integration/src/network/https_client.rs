// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bytes::Bytes;
use http::{Response, Uri};
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use s2n_tls::{
    config::Config,
    security::{self, Policy},
};
use s2n_tls_hyper::connector::HttpsConnector;
use std::str::FromStr;

/// The set of well known http sites that we attempt to connect to.
///
/// This test is only concerned with TLS handshake compatibility, so we don't
/// assert on specific HTTP status codes. Sites frequently change their behavior
/// (e.g. throttling the IP ranges of our CI providers), which makes asserting on
/// specific status codes flaky. Instead, we only require that the request
/// completes with _some_ HTTP status code, which indicates that the TLS
/// handshake succeeded.
const TEST_TARGETS: &[&str] = &[
    // this is a link to the s2n-tls unit test coverage report, hosted on cloudfront
    "https://dx1inn44oyl7n.cloudfront.net/main/index.html",
    // this is a link to a non-existent S3 item
    "https://notmybucket.s3.amazonaws.com/folder/afile.jpg",
    "https://www.amazon.com",
    "https://www.apple.com",
    "https://www.att.com",
    "https://www.cloudflare.com",
    "https://www.ebay.com",
    "https://www.google.com",
    "https://www.mozilla.org",
    "https://www.netflix.com",
    "https://www.openssl.org",
    "https://www.t-mobile.com",
    "https://www.verizon.com",
    "https://www.wikipedia.org",
    "https://www.yahoo.com",
    "https://www.youtube.com",
    "https://www.github.com",
    "https://www.samsung.com",
    "https://www.twitter.com",
    "https://www.facebook.com",
    "https://www.microsoft.com",
    "https://www.ibm.com",
    "https://www.f5.com",
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
/// a number of well known http sites. We only assert that the request completes
/// with some recognizable HTTP status code, which indicates that the TLS
/// handshake succeeded. We intentionally do _not_ assert on specific status
/// codes, since sites frequently change their behavior and cause flaky failures.
#[test_log::test(tokio::test)]
async fn https_get_test() -> Result<(), Box<dyn std::error::Error>> {
    for target in TEST_TARGETS {
        for policy in [security::DEFAULT, security::DEFAULT_TLS13] {
            tracing::info!("executing test case {target:?} with {policy:?}");

            let response = https_get(target, &policy).await.map_err(|err| {
                format!("HTTPS request to {target:?} with {policy:?} failed: {err}")
            })?;

            let status_code = response.status();
            tracing::info!("received status code {status_code} for {target:?}");
        }
    }

    Ok(())
}
