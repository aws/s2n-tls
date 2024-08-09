// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bytes::Bytes;
use http::{status, Uri};
use http_body_util::{BodyExt, Empty};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use s2n_tls::config::Config;
use s2n_tls_hyper::connector::HttpsConnector;
use std::{error::Error, str::FromStr};

#[tokio::test]
async fn test_get_request() -> Result<(), Box<dyn Error>> {
    let connector = HttpsConnector::new(Config::default());
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(connector);

    let uri = Uri::from_str("https://www.amazon.com")?;
    let response = client.get(uri).await?;
    assert_eq!(response.status(), status::StatusCode::OK);

    let body = response.into_body().collect().await?.to_bytes();
    assert!(!body.is_empty());

    Ok(())
}
