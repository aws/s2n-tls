// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use std::error::Error;
use std::str::FromStr;

/// NOTE: this CA is to be used for demonstration purposes only!
const CA: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../certs/ca-cert.pem"));

#[derive(Parser)]
struct Args {
    #[clap(short, long, default_value = "localhost:8888")]
    addr: String,
    #[clap(short, long, default_value = "")]
    body: String,
}

async fn run_client(addr: &str, request_body: Vec<u8>) -> Result<(), Box<dyn Error>> {
    // Configure the s2n-tls client.
    let config = {
        let mut builder = s2n_tls::config::Builder::new();
        builder.trust_pem(CA)?;
        builder.build()?
    };

    // Create a hyper-util client with this configuration, using the s2n-tls-hyper HttpsConnector.
    let connector = s2n_tls_hyper::connector::HttpsConnector::new(config);
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(connector);

    // Create an HTTP request to send to the server.
    let uri = http::Uri::from_str(format!("https://{addr}/").as_str())?;
    let request: http::Request<Full<Bytes>> = http::Request::builder()
        .method(http::Method::GET)
        .uri(uri)
        .body(Full::from(request_body.clone()))?;

    // Send the request to the server.
    let response = client.request(request).await?;
    assert_eq!(response.status(), http::StatusCode::OK);

    // Get the response body.
    let response_body = response.into_body().collect().await?.to_bytes();
    println!(
        "Response body: \n{}",
        String::from_utf8_lossy(&response_body)
    );

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    run_client(&args.addr, args.body.into_bytes()).await?;
    Ok(())
}
