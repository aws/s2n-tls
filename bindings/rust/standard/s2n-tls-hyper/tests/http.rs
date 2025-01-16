// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::common::{echo::echo, InsecureAcceptAllCertificatesHandler};
use bytes::Bytes;
use common::echo::serve_echo;
use http::{Method, Request, Uri, Version};
use http_body_util::{BodyExt, Empty, Full};
use hyper::service::service_fn;
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo},
};
use s2n_tls::{
    callbacks::{ClientHelloCallback, ConnectionFuture},
    config,
    connection::Connection,
    security::DEFAULT_TLS13,
};
use s2n_tls_hyper::{connector::HttpsConnector, error};
use std::{error::Error, pin::Pin, str::FromStr};
use tokio::{
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};

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

/// This test covers the general customer TLS Error experience. We want to
/// confirm that s2n-tls errors are correctly bubbled up and that details can be
/// extracted/matched on.
#[tokio::test]
async fn error_matching() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (server_task, addr) = {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server_task = tokio::spawn(serve_echo(listener, common::config()?.build()?));
        (server_task, addr)
    };

    let client_task: JoinHandle<Result<(), Box<dyn Error + Send + Sync>>> =
        tokio::spawn(async move {
            // the client config won't trust the self-signed cert that the server
            // uses.
            let client_config = {
                let mut builder = config::Config::builder();
                builder.set_security_policy(&DEFAULT_TLS13)?;
                builder.set_max_blinding_delay(0)?;
                builder.build()?
            };

            let connector = HttpsConnector::new(client_config);
            let client: Client<_, Empty<Bytes>> =
                Client::builder(TokioExecutor::new()).build(connector);

            let uri = Uri::from_str(format!("https://localhost:{}", addr.port()).as_str())?;
            client.get(uri).await?;

            panic!("the client request should fail");
        });

    // expected error:
    // hyper_util::client::legacy::Error(
    //     Connect,
    //     TlsError(
    //         Error {
    //             code: 335544366,
    //             name: "S2N_ERR_CERT_UNTRUSTED",
    //             message: "Certificate is untrusted",
    //             kind: ProtocolError,
    //             source: Library,
    //             debug: "Error encountered in lib/tls/s2n_x509_validator.c:721",
    //             errno: "No such file or directory",
    //         },
    //     ),
    // )
    let client_response = client_task.await?;
    let client_error = client_response.unwrap_err();
    let hyper_error: &hyper_util::client::legacy::Error = client_error.downcast_ref().unwrap();

    // the error happened when attempting to connect to the endpoint.
    assert!(hyper_error.is_connect());

    let error_source = hyper_error.source().unwrap();
    let s2n_tls_hyper_error: &s2n_tls_hyper::error::Error = error_source.downcast_ref().unwrap();

    let s2n_tls_error = match s2n_tls_hyper_error {
        s2n_tls_hyper::error::Error::TlsError(s2n_tls_error) => s2n_tls_error,
        _ => panic!("unexpected error type"),
    };

    assert_eq!(
        s2n_tls_error.kind(),
        s2n_tls::error::ErrorType::ProtocolError
    );
    assert_eq!(s2n_tls_error.name(), "S2N_ERR_CERT_UNTRUSTED");

    server_task.abort();
    Ok(())
}

#[tokio::test]
async fn ipv6() -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = {
        // The localhost IPv6 certificate contains ::1 in the SAN extension. s2n-tls will not
        // successfully validate the certificate unless the sever name is properly formatted, and
        // matches this identity.
        let localhost_ipv6_cert: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../certs/cert_localhost_ipv6.pem"
        ));
        let localhost_ipv6_key: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../certs/key_localhost_ipv6.pem"
        ));

        let mut builder = config::Config::builder();
        builder.load_pem(localhost_ipv6_cert, localhost_ipv6_key)?;
        builder.trust_pem(localhost_ipv6_cert)?;
        builder.build()?
    };

    // Listen for IPv6 connections.
    let listener = TcpListener::bind("[::1]:0").await?;
    let addr = listener.local_addr()?;

    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(serve_echo(listener, config.clone()));

    tasks.spawn(async move {
        let connector = HttpsConnector::new(config);
        let client: Client<_, Empty<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);

        // Connect to the localhost IPv6 address. s2n-tls hostname verification should ensure that
        // the certificate contains the `::1` identity (without square brackets).
        let uri = Uri::from_str(format!("https://[::1]:{}", addr.port()).as_str())?;
        let response = client.get(uri).await?;
        assert_eq!(response.status(), 200);

        Ok(())
    });

    while let Some(res) = tasks.join_next().await {
        res.unwrap()?;
    }

    Ok(())
}

#[tokio::test]
async fn http2() -> Result<(), Box<dyn Error + Send + Sync>> {
    for expected_http_version in [Version::HTTP_11, Version::HTTP_2] {
        let server_config = {
            let mut builder = common::config()?;
            if expected_http_version == Version::HTTP_2 {
                builder.set_application_protocol_preference(["h2"])?;
            }
            builder.build()?
        };

        common::echo::make_echo_request(server_config.clone(), |port| async move {
            let connector = HttpsConnector::new(common::config()?.build()?);
            let client: Client<_, Empty<Bytes>> =
                Client::builder(TokioExecutor::new()).build(connector);

            let uri = Uri::from_str(format!("https://localhost:{}", port).as_str())?;
            let response = client.get(uri).await?;
            assert_eq!(response.status(), 200);

            // Ensure that HTTP/2 is negotiated when supported by the server.
            assert_eq!(response.version(), expected_http_version);

            Ok(())
        })
        .await?;
    }

    Ok(())
}

/// Ensure that HTTP/2 is negotiated, regardless of any pre-configured ALPN values.
#[tokio::test]
async fn config_alpn_ignored() -> Result<(), Box<dyn Error + Send + Sync>> {
    let server_config = {
        let mut builder = common::config()?;
        builder.set_application_protocol_preference(["h2"])?;
        builder.build()?
    };

    common::echo::make_echo_request(server_config, |port| async move {
        let client_config = {
            let mut builder = common::config()?;
            // Set an arbitrary non-HTTP/2 ALPN value.
            builder.set_application_protocol_preference([b"http/1.1"])?;
            builder.build()?
        };

        let connector = HttpsConnector::new(client_config);
        let client: Client<_, Empty<Bytes>> =
            Client::builder(TokioExecutor::new()).build(connector);

        let uri = Uri::from_str(format!("https://localhost:{}", port).as_str())?;
        let response = client.get(uri).await?;
        assert_eq!(response.status(), 200);

        // Ensure that HTTP/2 was negotiated.
        assert_eq!(response.version(), Version::HTTP_2);

        Ok(())
    })
    .await?;

    Ok(())
}

#[tokio::test]
async fn plaintext_http() -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let mut tasks: JoinSet<Result<(), Box<dyn Error + Send + Sync>>> = JoinSet::new();
    tasks.spawn(async move {
        // Listen for HTTP requests on a plain TCP stream.
        let (tcp_stream, _) = listener.accept().await.unwrap();
        let server = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
        server
            .serve_connection(TokioIo::new(tcp_stream), service_fn(echo))
            .await?;

        Ok(())
    });

    tasks.spawn(async move {
        for enable_plaintext_http in [false, true] {
            let connector = {
                let config = common::config()?.build()?;
                let mut builder = HttpsConnector::builder(config);
                builder.with_plaintext_http(enable_plaintext_http);
                builder.build()
            };

            let client: Client<_, Empty<Bytes>> =
                Client::builder(TokioExecutor::new()).build(connector);
            let uri = Uri::from_str(format!("http://127.0.0.1:{}", addr.port()).as_str())?;
            let response = client.get(uri).await;

            if enable_plaintext_http {
                // If plaintext HTTP is enabled, the request should succeed.
                let response = response.unwrap();
                assert_eq!(response.status(), 200);
            } else {
                // If plaintext HTTP is disabled, the request should error.
                let error = response.unwrap_err();

                // Ensure an InvalidScheme error is produced.
                let error = error
                    .source()
                    .unwrap()
                    .downcast_ref::<error::Error>()
                    .unwrap();
                assert!(matches!(error, error::Error::InvalidScheme));
                assert!(!error.to_string().is_empty());
            }
        }

        Ok(())
    });

    while let Some(res) = tasks.join_next().await {
        res.unwrap()?;
    }

    Ok(())
}
