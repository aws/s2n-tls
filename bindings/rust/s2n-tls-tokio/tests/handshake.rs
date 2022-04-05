// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::raw::{config::Config, connection::Version, error::Error, security::DEFAULT_TLS13};
use s2n_tls_tokio::{TlsAcceptor, TlsConnector, TlsStream};
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

async fn get_streams() -> Result<(TcpStream, TcpStream), tokio::io::Error> {
    let localhost = "127.0.0.1".to_owned();
    let listener = TcpListener::bind(format!("{}:0", localhost)).await?;
    let addr = listener.local_addr()?;
    let client_stream = TcpStream::connect(&addr).await?;
    let (server_stream, _) = listener.accept().await?;
    Ok((server_stream, client_stream))
}

async fn run_client(config: Config, stream: TcpStream) -> Result<TlsStream<TcpStream>, Error> {
    let client = TlsConnector::new(config);
    client.connect("localhost", stream).await
}

async fn run_server(config: Config, stream: TcpStream) -> Result<TlsStream<TcpStream>, Error> {
    let server = TlsAcceptor::new(config);
    server.accept(stream).await
}

#[tokio::test]
async fn handshake_basic() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = get_streams().await?;

    let mut client_config = Config::builder();
    client_config.set_security_policy(&DEFAULT_TLS13)?;
    client_config.trust_pem(CERT_PEM)?;
    unsafe {
        client_config.disable_x509_verification()?;
    }
    let client_config = client_config.build()?;

    let mut server_config = Config::builder();
    server_config.set_security_policy(&DEFAULT_TLS13)?;
    server_config.load_pem(CERT_PEM, KEY_PEM)?;
    let server_config = server_config.build()?;

    let (client_result, server_result) = tokio::try_join!(
        run_client(client_config, client_stream),
        run_server(server_config, server_stream)
    )?;

    for tls in [client_result, server_result] {
        // Security policy ensures TLS1.3.
        assert_eq!(tls.conn.actual_protocol_version()?, Version::TLS13);
        // Handshake types may change, but will at least be negotiated.
        assert!(tls.conn.handshake_type()?.contains("NEGOTIATED"));
        // Cipher suite may change, so just makes sure we can retrieve it.
        assert!(tls.conn.cipher_suite().is_ok());
    }

    Ok(())
}
