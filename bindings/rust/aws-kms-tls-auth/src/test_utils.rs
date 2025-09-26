// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    epoch_schedule,
    psk_derivation::{EpochSecret, PskIdentity},
    psk_parser::retrieve_psk_identities,
    DecodeValue, PskProvider,
};
use aws_lc_rs::hmac;
use aws_sdk_kms::{operation::generate_mac::GenerateMacOutput, primitives::Blob, Client};
use aws_smithy_mocks::{mock, mock_client, Rule, RuleMode};
use s2n_tls::{
    callbacks::{ClientHelloCallback, ConnectionFuture},
    config::ConnectionInitializer,
    error::Error as S2NError,
};
use s2n_tls_tokio::TlsStream;
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

////////////////////////////////////////////////////////////////////////////////
//////////////////////////    test constants   /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

pub const KMS_KEY_ARN_A: &str =
    "arn:aws:kms:us-west-2:111122223333:key/98179871-91827391873-918279187";
pub const KMS_KEY_ARN_B: &str =
    "arn:aws:kms:us-west-2:111122223333:key/abcd-lkajdlsakjdlkj-kasjhdfkjh";
pub const KEY_A_MATERIAL: &[u8] = b"some random key bytes";
pub const KEY_B_MATERIAL: &[u8] = b"some other random bytes";

#[derive(Debug, Clone)]
struct MockKmsKey {
    pub arn: &'static str,
    pub material: &'static [u8],
}
const KMS_KEY_A: MockKmsKey = MockKmsKey {
    arn: KMS_KEY_ARN_A,
    material: KEY_A_MATERIAL,
};

const KMS_KEY_B: MockKmsKey = MockKmsKey {
    arn: KMS_KEY_ARN_B,
    material: KEY_B_MATERIAL,
};

const MOCKED_EPOCH_COUNT: u64 = 100;

////////////////////////////////////////////////////////////////////////////////
/////////////////////////    mocks & fixtures   ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/// Mock the "generateMAC" operation for `key` on `message`.
fn construct_rule(key: MockKmsKey, message: u64) -> Rule {
    let mac = {
        let s_key = hmac::Key::new(hmac::HMAC_SHA384, key.material);
        let tag = hmac::sign(&s_key, &message.to_be_bytes());
        tag.as_ref().to_vec()
    };

    let message = Blob::new(message.to_be_bytes().to_vec());
    let mac = Blob::new(mac);

    mock!(Client::generate_mac)
        .match_requests(move |req| req.key_id() == Some(key.arn) && req.message() == Some(&message))
        .then_output(move || GenerateMacOutput::builder().mac(mac.clone()).build())
}

/// a fake KMS client that allows MAC generation for a range of epochs.
pub fn mocked_kms_client() -> Client {
    let mut rules = Vec::new();

    let current_epoch = epoch_schedule::current_epoch();

    for epoch in (current_epoch - 5)..=(current_epoch + MOCKED_EPOCH_COUNT) {
        for key in [KMS_KEY_A, KMS_KEY_B] {
            rules.push(construct_rule(key, epoch));
        }
    }

    let rule_ref: Vec<&Rule> = rules.iter().collect();

    mock_client!(aws_sdk_kms, RuleMode::MatchAny, rule_ref)
}

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

#[derive(Debug, Default, Clone)]
pub struct PskIdentityObserver(pub Arc<Mutex<Vec<PskIdentity>>>);
impl s2n_tls::callbacks::ClientHelloCallback for PskIdentityObserver {
    fn on_client_hello(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, S2NError> {
        let raw_identities = retrieve_psk_identities(connection.client_hello()?).unwrap();
        let first_identity = raw_identities.list().first().unwrap();
        let psk_identity = PskIdentity::decode_from_exact(first_identity.identity.blob()).unwrap();
        self.0.lock().unwrap().push(psk_identity);
        Err(S2NError::application("nothing to handshake".into()))
    }
}

/// Sanity check to make sure that mocking is set up correctly.
#[tokio::test]
async fn deterministic_fetch() {
    let this_epoch = epoch_schedule::current_epoch();
    let secret_a = EpochSecret::fetch_epoch_secret(
        &mocked_kms_client(),
        &KMS_KEY_ARN_A.to_owned(),
        this_epoch,
    )
    .await
    .unwrap();
    let secret_b = EpochSecret::fetch_epoch_secret(
        &mocked_kms_client(),
        &KMS_KEY_ARN_A.to_owned(),
        this_epoch,
    )
    .await
    .unwrap();
    assert_eq!(secret_a, secret_b);
}
