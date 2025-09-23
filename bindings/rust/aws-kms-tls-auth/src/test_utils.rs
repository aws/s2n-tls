// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{
    callbacks::ClientHelloCallback, config::ConnectionInitializer, error::Error as S2NError,
};
use s2n_tls_tokio::TlsStream;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////    test constants   /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

pub const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

////////////////////////////////////////////////////////////////////////////////
/////////////////////////    s2n-tls utilities   ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////

pub fn configs_from_callbacks(
    client_psk_provider: impl ConnectionInitializer,
    server_psk_receiver: impl ClientHelloCallback,
) -> (s2n_tls::config::Config, s2n_tls::config::Config) {
    let mut client_config = s2n_tls::config::Builder::new();
    client_config
        .set_connection_initializer(client_psk_provider)
        .unwrap();
    client_config
        .set_security_policy(&s2n_tls::security::DEFAULT_TLS13)
        .unwrap();
    let client_config = client_config.build().unwrap();

    let mut server_config = s2n_tls::config::Builder::new();
    server_config
        .set_client_hello_callback(server_psk_receiver)
        .unwrap();
    server_config
        .set_security_policy(&s2n_tls::security::DEFAULT_TLS13)
        .unwrap();
    let server_config = server_config.build().unwrap();

    (client_config, server_config)
}

/// Handshake two configs over localhost sockets, returning any errors encountered.
///
/// If the connection is successful, the server's tcp stream is returned which can
/// be used to inspect the client hello
///
/// The server error is preferred if available.
pub async fn handshake(
    client_config: &s2n_tls::config::Config,
    server_config: &s2n_tls::config::Config,
) -> Result<TlsStream<TcpStream>, S2NError> {
    const SERVER_MESSAGE: &[u8] = b"hello from server";
    let client = s2n_tls_tokio::TlsConnector::new(client_config.clone());
    let server = s2n_tls_tokio::TlsAcceptor::new(server_config.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::task::spawn(async move {
        let (stream, _peer_addr) = listener.accept().await.unwrap();
        let mut tls = server.accept(stream).await?;
        tls.write_all(SERVER_MESSAGE).await.unwrap();
        tls.shutdown().await.unwrap();
        Ok::<TlsStream<TcpStream>, S2NError>(tls)
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut client_result = client.connect("localhost", stream).await;
    if let Ok(tls) = client_result.as_mut() {
        let mut buffer = [0; SERVER_MESSAGE.len()];
        tls.read_exact(&mut buffer).await.unwrap();
        assert_eq!(buffer, SERVER_MESSAGE);
        tls.shutdown().await.unwrap();
    }

    // check the server status first, because it has the interesting errors
    let stream = server.await.unwrap()?;
    client_result?;

    Ok(stream)
}
