// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::S2NError;
use crate::{identity::ObfuscationKey, receiver::PskReceiver, PskProvider};
use aws_sdk_kms::{
    operation::{decrypt::DecryptOutput, generate_data_key::GenerateDataKeyOutput},
    primitives::Blob,
    Client,
};
use aws_smithy_mocks::{mock, mock_client, Rule};
use std::sync::LazyLock;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////    test constants   /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

pub const CIPHERTEXT_DATAKEY: &[u8] = b"im ciphertext yes sir i am";
pub const PLAINTEXT_DATAKEY: &[u8] = b"hehe very secret, yes that's me";
pub const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
pub static OBFUSCATION_KEY: LazyLock<ObfuscationKey> =
    LazyLock::new(ObfuscationKey::random_test_key);

////////////////////////////////////////////////////////////////////////////////
/////////////////////////    mocks & fixtures   ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

pub fn decrypt_mocks() -> (Rule, Client) {
    let decrypt_rule = mock!(aws_sdk_kms::Client::decrypt).then_output(|| {
        DecryptOutput::builder()
            .key_id(KMS_KEY_ARN)
            .plaintext(Blob::new(PLAINTEXT_DATAKEY))
            .build()
    });
    let decrypt_client = mock_client!(aws_sdk_kms, [&decrypt_rule]);
    (decrypt_rule, decrypt_client)
}

pub fn gdk_mocks() -> (Rule, Client) {
    let gdk_rule = mock!(aws_sdk_kms::Client::generate_data_key).then_output(|| {
        GenerateDataKeyOutput::builder()
            .plaintext(Blob::new(PLAINTEXT_DATAKEY))
            .ciphertext_blob(Blob::new(CIPHERTEXT_DATAKEY))
            .build()
    });
    let gdk_client = mock_client!(aws_sdk_kms, [&gdk_rule]);
    (gdk_rule, gdk_client)
}

pub async fn test_psk_provider() -> PskProvider {
    let (_gdk_rule, gdk_client) = gdk_mocks();
    PskProvider::initialize(gdk_client, KMS_KEY_ARN.to_string(), OBFUSCATION_KEY.clone())
        .await
        .unwrap()
}

////////////////////////////////////////////////////////////////////////////////
/////////////////////////    s2n-tls UTILITIES   ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////

pub fn configs_from_callbacks(
    client_psk_provider: PskProvider,
    server_psk_receiver: PskReceiver,
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
/// The server error is preferred if available.
pub async fn handshake(
    client_config: &s2n_tls::config::Config,
    server_config: &s2n_tls::config::Config,
) -> Result<(), S2NError> {
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
        Ok::<(), S2NError>(())
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
    server.await.unwrap()?;
    client_result?;

    Ok(())
}
