// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::common::InsecureAcceptAllCertificatesHandler;
use bytes::Bytes;
use http::{Method, Request, Uri};
use http_body_util::{BodyExt, Empty, Full};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use s2n_tls::{
    callbacks::{ClientHelloCallback, ConnectionFuture},
    connection::Connection,
};
use s2n_tls_hyper::connector::HttpsConnector;
use std::{error::Error, pin::Pin, str::FromStr};

pub mod common;

const TEST_DATA: &[u8] = "hello world".as_bytes();

// The maximum TLS record payload is 2^14 bytes.
// Send more to ensure multiple records.
const LARGE_TEST_DATA: &[u8] = &[5; (1 << 15)];

#[tokio::test]
async fn test_get_request() -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = common::config()?.build()?;
    common::echo::make_echo_request(config.clone(), |port| async move {
        let connector = HttpsConnector::new(config.clone());
        let client: Client<_, Empty<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);

        let uri = Uri::from_str(format!("https://localhost:{}", port).as_str())?;
        let response = client.get(uri).await?;
        assert_eq!(response.status(), 200);

        Ok(())
    })
    .await?;

    Ok(())
}

#[tokio::test]
async fn test_http_methods() -> Result<(), Box<dyn Error + Send + Sync>> {
    let methods = [Method::GET, Method::POST, Method::PUT, Method::DELETE];
    for method in methods {
        let config = common::config()?.build()?;
        common::echo::make_echo_request(config.clone(), |port| async move {
            let connector = HttpsConnector::new(config.clone());
            let client: Client<_, Full<Bytes>> =
                Client::builder(TokioExecutor::new()).build(connector);
            let request: Request<Full<Bytes>> = Request::builder()
                .method(method)
                .uri(Uri::from_str(
                    format!("https://localhost:{}", port).as_str(),
                )?)
                .body(Full::from(TEST_DATA))?;

            let response = client.request(request).await?;
            assert_eq!(response.status(), 200);

            let body = response.into_body().collect().await?.to_bytes();
            assert_eq!(body.to_vec().as_slice(), TEST_DATA);

            Ok(())
        })
        .await?;
    }

    Ok(())
}

#[tokio::test]
async fn test_large_request() -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = common::config()?.build()?;
    common::echo::make_echo_request(config.clone(), |port| async move {
        let connector = HttpsConnector::new(config.clone());
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(connector);
        let request: Request<Full<Bytes>> = Request::builder()
            .method(Method::POST)
            .uri(Uri::from_str(
                format!("https://localhost:{}", port).as_str(),
            )?)
            .body(Full::from(LARGE_TEST_DATA))?;

        let response = client.request(request).await?;
        assert_eq!(response.status(), 200);

        let body = response.into_body().collect().await?.to_bytes();
        assert_eq!(body.to_vec().as_slice(), LARGE_TEST_DATA);

        Ok(())
    })
    .await?;

    Ok(())
}

#[tokio::test]
async fn test_sni() -> Result<(), Box<dyn Error + Send + Sync>> {
    struct TestClientHelloHandler {
        expected_server_name: &'static str,
    }
    impl ClientHelloCallback for TestClientHelloHandler {
        fn on_client_hello(
            &self,
            connection: &mut Connection,
        ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
            let server_name = connection.server_name().unwrap();
            assert_eq!(server_name, self.expected_server_name);
            Ok(None)
        }
    }

    for hostname in ["localhost", "127.0.0.1"] {
        let mut config = common::config()?;
        config.set_client_hello_callback(TestClientHelloHandler {
            // Ensure that the HttpsConnector correctly sets the SNI according to the hostname in
            // the URI.
            expected_server_name: hostname,
        })?;
        config.set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;
        let config = config.build()?;

        common::echo::make_echo_request(config.clone(), |port| async move {
            let connector = HttpsConnector::new(config.clone());
            let client: Client<_, Empty<Bytes>> =
                Client::builder(TokioExecutor::new()).build(connector);

            let uri = Uri::from_str(format!("https://{}:{}", hostname, port).as_str())?;
            let response = client.get(uri).await?;
            assert_eq!(response.status(), 200);

            Ok(())
        })
        .await?;
    }

    Ok(())
}
