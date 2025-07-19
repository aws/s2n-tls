// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::identity::PskVersion;
use crate::{identity::ObfuscationKey, receiver::PskReceiver, PskProvider};
use crate::{S2NError, AES_256_GCM_SIV_KEY_LEN};
use aws_sdk_kms::{
    operation::{decrypt::DecryptOutput, generate_data_key::GenerateDataKeyOutput},
    primitives::Blob,
    Client,
};
use aws_smithy_mocks::{mock, mock_client, Rule};
use s2n_tls::config::ConnectionInitializer;
use s2n_tls_tokio::TlsStream;
use std::sync::LazyLock;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////    test constants   /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

pub const CIPHERTEXT_DATAKEY_A: &[u8] = b"ciphertext A <aksjdhkajhd>";
pub const PLAINTEXT_DATAKEY_A: &[u8] = b"plaintext A <ijnhgvytgfcrdx>";

pub const CIPHERTEXT_DATAKEY_B: &[u8] = b"ciphertext B <48udhygtrjbdrndiu>";
pub const PLAINTEXT_DATAKEY_B: &[u8] = b"plaintext B <9876trfgyt543wsxdfr>";

pub const KMS_KEY_ARN: &str =
    "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
pub static OBFUSCATION_KEY: LazyLock<ObfuscationKey> =
    LazyLock::new(ObfuscationKey::random_test_key);

/// used to obfuscate the checked in identity in `resources/psk_identity.bin`
pub static CONSTANT_OBFUSCATION_KEY: LazyLock<ObfuscationKey> = LazyLock::new(|| {
    const OBFUSCATION_KEY_NAME: &[u8] = b"alice the obfuscator";
    const OBFUSCATION_KEY_MATERIAL: [u8; AES_256_GCM_SIV_KEY_LEN] = [
        91, 109, 160, 46, 132, 41, 29, 134, 11, 41, 208, 78, 101, 132, 138, 80, 88, 32, 182, 207,
        80, 45, 37, 93, 83, 11, 69, 218, 200, 203, 55, 66,
    ];
    ObfuscationKey::new(
        OBFUSCATION_KEY_NAME.to_vec(),
        OBFUSCATION_KEY_MATERIAL.to_vec(),
    )
    .unwrap()
});

pub static GDK_OUTPUT_A: LazyLock<GenerateDataKeyOutput> = LazyLock::new(|| {
    GenerateDataKeyOutput::builder()
        .plaintext(Blob::new(PLAINTEXT_DATAKEY_A))
        .ciphertext_blob(Blob::new(CIPHERTEXT_DATAKEY_A))
        .build()
});

pub static GDK_OUTPUT_B: LazyLock<GenerateDataKeyOutput> = LazyLock::new(|| {
    GenerateDataKeyOutput::builder()
        .plaintext(Blob::new(PLAINTEXT_DATAKEY_B))
        .ciphertext_blob(Blob::new(CIPHERTEXT_DATAKEY_B))
        .build()
});

pub static DECRYPT_OUTPUT_A: LazyLock<DecryptOutput> = LazyLock::new(|| {
    DecryptOutput::builder()
        .key_id(KMS_KEY_ARN)
        .plaintext(Blob::new(PLAINTEXT_DATAKEY_A))
        .build()
});

pub static DECRYPT_OUTPUT_B: LazyLock<DecryptOutput> = LazyLock::new(|| {
    DecryptOutput::builder()
        .key_id(KMS_KEY_ARN)
        .plaintext(Blob::new(PLAINTEXT_DATAKEY_B))
        .build()
});

////////////////////////////////////////////////////////////////////////////////
/////////////////////////    mocks & fixtures   ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

pub fn decrypt_mocks() -> (Rule, Client) {
    let decrypt_rule = mock!(aws_sdk_kms::Client::decrypt).then_output(|| DECRYPT_OUTPUT_A.clone());
    let decrypt_client = mock_client!(aws_sdk_kms, [&decrypt_rule]);
    (decrypt_rule, decrypt_client)
}

pub fn gdk_mocks() -> (Rule, Client) {
    let gdk_rule =
        mock!(aws_sdk_kms::Client::generate_data_key).then_output(|| GDK_OUTPUT_A.clone());
    let gdk_client = mock_client!(aws_sdk_kms, [&gdk_rule]);
    (gdk_rule, gdk_client)
}

pub async fn test_psk_provider() -> PskProvider {
    let (_gdk_rule, gdk_client) = gdk_mocks();
    PskProvider::initialize(
        PskVersion::V1,
        gdk_client,
        KMS_KEY_ARN.to_string(),
        OBFUSCATION_KEY.clone(),
        |_| {},
    )
    .await
    .unwrap()
}

////////////////////////////////////////////////////////////////////////////////
/////////////////////////    s2n-tls utilities   ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////

pub fn configs_from_callbacks(
    client_psk_provider: impl ConnectionInitializer,
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
