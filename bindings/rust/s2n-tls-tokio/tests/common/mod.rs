// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::raw::{config, error::Error, security::DEFAULT_TLS13};
use s2n_tls_tokio::{Config, TlsAcceptor, TlsConnector, TlsStream};
use tokio::net::{TcpListener, TcpStream};

/// NOTE: this certificate and key are used for testing purposes only!
pub static CERT_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/certs/cert.pem"
));
pub static KEY_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/certs/key.pem"
));

pub async fn get_streams() -> Result<(TcpStream, TcpStream), tokio::io::Error> {
    let localhost = "127.0.0.1".to_owned();
    let listener = TcpListener::bind(format!("{}:0", localhost)).await?;
    let addr = listener.local_addr()?;
    let client_stream = TcpStream::connect(&addr).await?;
    let (server_stream, _) = listener.accept().await?;
    Ok((server_stream, client_stream))
}

pub fn client_config() -> Result<config::Builder, Error> {
    let mut builder = config::Config::builder();
    builder.set_security_policy(&DEFAULT_TLS13)?;
    builder.trust_pem(CERT_PEM)?;
    Ok(builder)
}

pub fn server_config() -> Result<config::Builder, Error> {
    let mut builder = config::Config::builder();
    builder.set_security_policy(&DEFAULT_TLS13)?;
    builder.load_pem(CERT_PEM, KEY_PEM)?;
    Ok(builder)
}

pub async fn run_negotiate<A: Config, B: Config>(
    client: TlsConnector<A>,
    client_stream: TcpStream,
    server: TlsAcceptor<B>,
    server_stream: TcpStream,
) -> Result<(TlsStream<TcpStream>, TlsStream<TcpStream>), Error> {
    tokio::try_join!(
        client.connect("localhost", client_stream),
        server.accept(server_stream)
    )
}
