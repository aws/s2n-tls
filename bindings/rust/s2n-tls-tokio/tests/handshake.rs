// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::raw::{config::Config, error::Error, security::DEFAULT_TLS13};
use s2n_tls_tokio::{TlsAcceptor, TlsConnector};
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

async fn run_client(stream: TcpStream) -> Result<(), Error> {
    let mut config = Config::builder();
    config.set_security_policy(&DEFAULT_TLS13)?;
    config.trust_pem(CERT_PEM)?;
    unsafe {
        config.disable_x509_verification()?;
    }

    let client = TlsConnector::new(config.build()?);
    client.connect("localhost", stream).await?;
    Ok(())
}

async fn run_server(stream: TcpStream) -> Result<(), Error> {
    let mut config = Config::builder();
    config.set_security_policy(&DEFAULT_TLS13)?;
    config.load_pem(CERT_PEM, KEY_PEM)?;

    let server = TlsAcceptor::new(config.build()?);
    server.accept(stream).await?;
    Ok(())
}

#[tokio::test]
async fn handshake_basic() -> Result<(), Error> {
    let localhost = "127.0.0.1".to_owned();
    let listener = TcpListener::bind(format!("{}:0", localhost)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_stream = TcpStream::connect(&addr).await.unwrap();
    let (server_stream, _) = listener.accept().await.unwrap();

    tokio::try_join!(run_client(client_stream), run_server(server_stream))?;
    Ok(())
}
