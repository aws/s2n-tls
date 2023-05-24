// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{
    config,
    connection::Builder,
    error::Error,
    security::{DEFAULT, DEFAULT_TLS13},
};
use s2n_tls_tokio::{TlsAcceptor, TlsConnector, TlsStream};
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
};

mod stream;
pub use stream::*;
mod time;
pub use time::*;

/// NOTE: this certificate and key are used for testing purposes only!
pub static CERT_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/certs/cert.pem"
));
pub static KEY_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/certs/key.pem"
));
pub static RSA_CERT_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/certs/cert_rsa.pem"
));
pub static RSA_KEY_PEM: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/certs/key_rsa.pem"
));

pub const MIN_BLINDING_SECS: Duration = Duration::from_secs(10);
pub const MAX_BLINDING_SECS: Duration = Duration::from_secs(30);

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

pub fn client_config_tls12() -> Result<config::Builder, Error> {
    let mut builder = config::Config::builder();
    builder.set_security_policy(&DEFAULT)?;
    builder.trust_pem(RSA_CERT_PEM)?;
    Ok(builder)
}

pub fn server_config_tls12() -> Result<config::Builder, Error> {
    let mut builder = config::Config::builder();
    builder.set_security_policy(&DEFAULT)?;
    builder.load_pem(RSA_CERT_PEM, RSA_KEY_PEM)?;
    Ok(builder)
}

pub async fn run_negotiate<A: Builder, B: Builder, C, D>(
    client: &TlsConnector<A>,
    client_stream: C,
    server: &TlsAcceptor<B>,
    server_stream: D,
) -> Result<(TlsStream<C, A::Output>, TlsStream<D, B::Output>), Error>
where
    <A as Builder>::Output: Unpin,
    <B as Builder>::Output: Unpin,
    C: AsyncRead + AsyncWrite + Unpin,
    D: AsyncRead + AsyncWrite + Unpin,
{
    let (client, server) = tokio::join!(
        client.connect("localhost", client_stream),
        server.accept(server_stream)
    );
    Ok((client?, server?))
}
