// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioExecutor;
use std::error::Error;
use tokio::net::TcpListener;

/// NOTE: this certificate and key are to be used for demonstration purposes only!
pub const CERT_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../certs/localhost-chain.pem"
));
pub const KEY_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../certs/localhost-key.pem"
));

#[derive(Parser)]
struct Args {
    #[clap(short, long, default_value = "localhost:8888")]
    addr: String,
}

/// Echo the request body back to the client in the response.
pub async fn echo(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    Ok(Response::new(req.into_body().boxed()))
}

async fn run_server(addr: &str) -> Result<(), Box<dyn Error>> {
    // Configure the s2n-tls server.
    let config = {
        let mut builder = s2n_tls::config::Builder::new();
        builder.load_pem(CERT_PEM, KEY_PEM)?;
        // Enable HTTP/2 by including it in the server's supported ALPN values. The "http2"
        // hyper-util feature must also be enabled.
        builder.set_application_protocol_preference([b"h2"])?;
        builder.build()?
    };

    // Create a TlsAcceptor based on this configuration.
    let acceptor = s2n_tls_tokio::TlsAcceptor::new(config);

    // Listen for incoming TCP connections at the provided address.
    let tcp_listener = TcpListener::bind(addr).await?;
    loop {
        // Wait for a client to connect.
        let (tcp, _) = tcp_listener.accept().await?;

        // Spawn a new task to handle the incoming TCP connection.
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            // Perform the TLS handshake.
            let tls_stream = acceptor.accept(tcp).await?;

            // Use the hyper server with the `echo` service to respond to the client's HTTP request
            // over the TlsStream.
            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let server = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
            server.serve_connection(io, service_fn(echo)).await?;

            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    run_server(&args.addr).await?;
    Ok(())
}
