// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    codec::DecodeValue,
    identity::{ObfuscationKey, PskIdentity},
    psk_from_material,
    psk_parser::retrieve_psk_identities,
    KeyArn, KEY_ROTATION_PERIOD, MAXIMUM_KEY_CACHE_SIZE,
};
use aws_sdk_kms::{primitives::Blob, Client};
use moka::sync::Cache;
use pin_project::pin_project;
use s2n_tls::{
    callbacks::{ClientHelloCallback, ConnectionFuture},
    error::Error as S2NError,
};
use std::{future::Future, pin::Pin, sync::Arc, task::Poll};

/// DecryptFuture wraps a future from the SDK into a format that s2n-tls understands
/// and can poll.
///
/// Specifically, it implements ConnectionFuture for the interior future type.
#[pin_project]
struct DecryptFuture<F> {
    #[pin]
    future: F,
}

impl<F> DecryptFuture<F>
where
    F: 'static + Send + Sync + Future<Output = anyhow::Result<s2n_tls::psk::Psk>>,
{
    pub fn new(future: F) -> Self {
        DecryptFuture { future }
    }
}

impl<F> s2n_tls::callbacks::ConnectionFuture for DecryptFuture<F>
where
    F: 'static + Send + Sync + Future<Output = anyhow::Result<s2n_tls::psk::Psk>>,
{
    fn poll(
        self: Pin<&mut Self>,
        connection: &mut s2n_tls::connection::Connection,
        ctx: &mut core::task::Context,
    ) -> std::task::Poll<Result<(), S2NError>> {
        let this = self.project();
        let psk = match this.future.poll(ctx) {
            Poll::Ready(Ok(psk)) => psk,
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(s2n_tls::error::Error::application(
                    e.into_boxed_dyn_error(),
                )));
            }
            Poll::Pending => return Poll::Pending,
        };
        connection.append_psk(&psk)?;
        Poll::Ready(Ok(()))
    }
}

/// The `PskReceiver` is used along with the [`PskProvider`] to perform TLS
/// 1.3 out-of-band PSK authentication, using PSK's generated from KMS.
///
/// This struct can be enabled on a config with [`s2n_tls::config::Builder::set_client_hello_callback`].
pub struct PskReceiver {
    kms_client: Client,
    obfuscation_keys: Vec<ObfuscationKey>,
    trusted_key_arns: Arc<Vec<KeyArn>>,
    /// The key_cache maps from the ciphertext datakey to the plaintext datakey.
    /// It has a bounded size, and will also evict items after 2 * KEY_ROTATION_PERIOD
    /// has elapsed.
    key_cache: Cache<Vec<u8>, Vec<u8>>,
}

impl PskReceiver {
    /// Create a new PskReceiver.
    ///
    /// This will receive the ciphertext datakey identities from a TLS client hello,
    /// then decrypt them using KMS. This establishes a mutually authenticated TLS
    /// handshake between parties with IAM permissions to generate and decrypt data keys
    ///
    /// * `kms_client`: The KMS Client that will be used for the decrypt calls
    /// * `obfuscation_keys`: The keys that will be used to deobfuscate the received
    ///                       identities. The client `PskProvider` must be using
    ///                       one of the obfuscation keys in this list. If the PskReceiver
    ///                       receives a Psk identity obfuscated using a key _not_
    ///                       on this list, then the handshake will fail.
    /// * `trusted_key_arns`: The list of KMS KeyArns that the PskReceiver will
    ///                      accept PSKs from. This is necessary because an attacker
    ///                      could grant the server decrypt permissions on AttackerKeyArn,
    ///                      but the PskReceiver should _not_ trust any Psk's
    ///                      from AttackerKeyArn.
    pub fn new(
        client: Client,
        trusted_key_arns: Vec<KeyArn>,
        obfuscation_keys: Vec<ObfuscationKey>,
    ) -> Self {
        let key_cache = moka::sync::Cache::builder()
            .max_capacity(MAXIMUM_KEY_CACHE_SIZE as u64)
            .time_to_live(KEY_ROTATION_PERIOD * 2)
            .build();
        Self {
            kms_client: client,
            trusted_key_arns: Arc::new(trusted_key_arns),
            obfuscation_keys,
            key_cache,
        }
    }

    /// This is the main async future that s2n-tls polls.
    ///
    /// It will
    /// 1. decrypt the ciphertext datakey
    /// 2. check that the decrypted material is associated with a trusted key id
    /// 3. cache the decrypted material in the key cache
    /// 4. return an s2n-tls psk
    ///
    /// All of the arguments are owned to satisfy the `'static` bound that s2n-tls
    /// requires on connection futures.
    async fn kms_decrypt_and_update(
        psk_identity: Vec<u8>,
        ciphertext_datakey: Vec<u8>,
        client: Client,
        trusted_key_arns: Arc<Vec<KeyArn>>,
        key_cache: Cache<Vec<u8>, Vec<u8>>,
    ) -> anyhow::Result<s2n_tls::psk::Psk> {
        let ciphertext_datakey_clone = ciphertext_datakey.clone();
        let decrypted = tokio::spawn(async move {
            client
                .decrypt()
                .ciphertext_blob(Blob::new(ciphertext_datakey_clone))
                .send()
                .await
        })
        .await??;

        // although the field is called `key_id`, it is actually the key arn. This
        // is confirmed in the documentation:
        // https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html#API_Decrypt_ResponseSyntax
        let associated_key_arn = decrypted.key_id.as_ref().unwrap();
        if !trusted_key_arns.contains(associated_key_arn) {
            anyhow::bail!("untrusted KMS Key: {associated_key_arn} is not trusted");
        }

        let plaintext_datakey = decrypted.plaintext.unwrap().into_inner();

        key_cache.insert(ciphertext_datakey, plaintext_datakey.clone());

        let psk = psk_from_material(&psk_identity, &plaintext_datakey).unwrap();

        Ok(psk)
    }
}

impl ClientHelloCallback for PskReceiver {
    fn on_client_hello(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
        // parse the identity list from the client hello
        let client_hello = connection.client_hello()?;
        let identities = match retrieve_psk_identities(client_hello) {
            Ok(identities) => identities,
            Err(e) => {
                return Err(s2n_tls::error::Error::application(e.into()));
            }
        };

        // extract the identity bytes
        let psk_identity = match identities.list().first() {
            Some(id) => id.identity.blob(),
            None => {
                return Err(s2n_tls::error::Error::application(
                    "identities list was zero-length".into(),
                ))
            }
        };

        // parse the identity bytes to a PskIdentity
        let identity = PskIdentity::decode_from_exact(psk_identity)
            .map_err(|e| s2n_tls::error::Error::application(e.into()))?;

        // deobfuscate the identity to get the ciphertext datakey
        let ciphertext_datakey = identity
            .deobfuscate_datakey(&self.obfuscation_keys)
            .map_err(|e| s2n_tls::error::Error::application(e.into()))?;

        let maybe_cached = self.key_cache.get(&ciphertext_datakey);
        if let Some(plaintext_datakey) = maybe_cached {
            // if we already had it cached, then append the PSK and return
            let psk = psk_from_material(psk_identity, &plaintext_datakey)?;
            connection.append_psk(&psk)?;
            Ok(None)
        } else {
            // otherwise return a future to decrypt with KMS
            let future = Self::kms_decrypt_and_update(
                psk_identity.to_vec(),
                ciphertext_datakey,
                self.kms_client.clone(),
                self.trusted_key_arns.clone(),
                self.key_cache.clone(),
            );
            let wrapped = DecryptFuture::new(future);
            Ok(Some(Box::pin(wrapped)))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        test_utils::{
            configs_from_callbacks, decrypt_mocks, gdk_mocks, handshake, test_psk_provider,
            CIPHERTEXT_DATAKEY, KMS_KEY_ARN, OBFUSCATION_KEY, PLAINTEXT_DATAKEY,
        },
        PskProvider,
    };

    use super::*;
    use aws_sdk_kms::{operation::decrypt::DecryptError, types::error::InvalidKeyUsageException};
    // https://docs.aws.amazon.com/sdk-for-rust/latest/dg/testing-smithy-mocks.html
    use aws_smithy_mocks::{mock, mock_client};

    /// When a new identity isn't in the cache, we
    /// 1. call KMS to decrypt it
    /// 2. store the result in the PSK
    /// When an identity is in the cache
    /// 1. no calls are made to KMS to decrypt it
    #[tokio::test]
    async fn decrypt_path() {
        let psk_provider = test_psk_provider().await;

        let (decrypt_rule, decrypt_client) = decrypt_mocks();
        let psk_receiver = PskReceiver::new(
            decrypt_client,
            vec![KMS_KEY_ARN.to_owned()],
            vec![OBFUSCATION_KEY.clone()],
        );

        let cache_handle = psk_receiver.key_cache.clone();

        let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_receiver);
        assert_eq!(decrypt_rule.num_calls(), 0);

        handshake(&client_config, &server_config).await.unwrap();
        assert_eq!(decrypt_rule.num_calls(), 1);
        assert_eq!(
            cache_handle.get(CIPHERTEXT_DATAKEY).unwrap().as_slice(),
            PLAINTEXT_DATAKEY
        );

        // no additional decrypt calls, the cached key was used
        handshake(&client_config, &server_config).await.unwrap();
        assert_eq!(decrypt_rule.num_calls(), 1);
    }

    // if the key ARN isn't recognized, then the handshake fails
    #[tokio::test]
    async fn untrusted_key_arn() {
        let psk_provider = test_psk_provider().await;

        let (_decrypt_rule, decrypt_client) = decrypt_mocks();
        let psk_receiver = PskReceiver::new(
            decrypt_client,
            // use an ARN different from the one KMS will return
            vec!["arn::wont-be-seen".to_string()],
            vec![OBFUSCATION_KEY.clone()],
        );

        let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_receiver);

        let err = handshake(&client_config, &server_config).await.unwrap_err();
        println!("{err}");
        assert!(err.to_string().contains("untrusted KMS Key: arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab is not trusted"));
    }

    #[tokio::test]
    async fn obfuscation_key_unavailable() {
        let psk_provider = test_psk_provider().await;

        // we configured the Psk Receiver with a different obfuscation key
        let (decrypt_rule, decrypt_client) = decrypt_mocks();
        let psk_receiver = PskReceiver::new(
            decrypt_client,
            vec![KMS_KEY_ARN.to_owned()],
            vec![ObfuscationKey::random_test_key()],
        );

        let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_receiver);

        let err = handshake(&client_config, &server_config).await.unwrap_err();
        // unable to deobfuscate: f6c9d1107f9b86a7bfbf836458d0483e not available
        assert!(err.to_string().starts_with("unable to deobfuscate: "));
        assert!(err.to_string().ends_with("not available"));

        // we should not have attempted to decrypt the key
        assert_eq!(decrypt_rule.num_calls(), 0)
    }

    // when the map is at capacity, old items are evicted when new ones are added
    #[tokio::test]
    async fn cache_max_capacity() {
        let (decrypt_rule, decrypt_client) = decrypt_mocks();
        let (_gdk_rule, gdk_client) = gdk_mocks();

        let obfuscation_key = ObfuscationKey::random_test_key();
        let psk_provider =
            PskProvider::initialize(gdk_client, KMS_KEY_ARN.to_string(), obfuscation_key.clone())
                .await
                .unwrap();

        let psk_receiver = PskReceiver::new(
            decrypt_client,
            vec![KMS_KEY_ARN.to_owned()],
            vec![obfuscation_key],
        );

        let cache_handle = psk_receiver.key_cache.clone();
        for i in 0..MAXIMUM_KEY_CACHE_SIZE {
            cache_handle.insert(i.to_be_bytes().to_vec(), i.to_be_bytes().to_vec());
        }
        cache_handle.run_pending_tasks();
        assert_eq!(cache_handle.entry_count(), MAXIMUM_KEY_CACHE_SIZE as u64);

        let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_receiver);

        assert_eq!(decrypt_rule.num_calls(), 0);
        handshake(&client_config, &server_config).await.unwrap();
        assert_eq!(decrypt_rule.num_calls(), 1);

        cache_handle.run_pending_tasks();
        assert_eq!(cache_handle.entry_count(), MAXIMUM_KEY_CACHE_SIZE as u64);
    }

    // when the decrypt operation fails, the handshake should also fail
    #[tokio::test]
    async fn decrypt_error() {
        let decrypt_rule = mock!(aws_sdk_kms::Client::decrypt).then_error(|| {
            DecryptError::InvalidKeyUsageException(InvalidKeyUsageException::builder().build())
        });
        let decrypt_client = mock_client!(aws_sdk_kms, [&decrypt_rule]);

        let psk_provider = test_psk_provider().await;

        let psk_receiver = PskReceiver::new(
            decrypt_client,
            vec![KMS_KEY_ARN.to_owned()],
            vec![OBFUSCATION_KEY.clone()],
        );

        let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_receiver);

        let decrypt_error = handshake(&client_config, &server_config).await.unwrap_err();
        assert!(decrypt_error.to_string().contains("service error"));
    }
}
