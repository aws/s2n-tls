// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{epoch_schedule, psk_derivation::EpochSecret, KeyArn, ONE_HOUR};
use aws_sdk_kms::Client;
use s2n_tls::{callbacks::ConnectionFuture, config::ConnectionInitializer};
use std::{
    cmp::min,
    collections::VecDeque,
    fmt::Debug,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

/// We aim to start using the key for epoch n after this duration has elapsed.
///
/// Consider a scenario where epoch n is exactly 30 minutes (1800 seconds) away.
/// If we slept for exactly 1800 seconds and checked the system clock again, epoch
/// n might not have started because System Clocks may be corrected, unreliable, etc.
///
/// This cushion reduces the chances of that happening.
const ROTATION_CUSHION: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct ProviderSecrets {
    key_arn: KeyArn,
    /// secret currently used to generate PSKs. Generally this is the epoch secret
    /// for the current epoch `n`.
    ///
    /// In the event of failure to fetch new epoch secrets, the client will continue
    /// using the existing key. The client does _not_ enforce a certain key lifetime,
    /// and will continue to make a best effort to connect.
    ///
    /// This means that clients are not responsible for enforcing the lifetime of
    /// epoch secrets, and that is controlled server-side.
    current_secret: RwLock<Arc<EpochSecret>>,
    /// secrets for epoch `n + 1` and `n + 2`
    next_secrets: Mutex<VecDeque<EpochSecret>>,
    smoothing_factor: Duration,
}

impl ProviderSecrets {
    fn current_secret(&self) -> Arc<EpochSecret> {
        self.current_secret.read().unwrap().clone()
    }

    fn available_epochs(&self) -> Vec<u64> {
        let mut epochs = Vec::new();
        epochs.push(self.current_secret().key_epoch);
        self.next_secrets
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.key_epoch)
            .for_each(|epoch| epochs.push(epoch));
        epochs
    }

    fn newest_available_epoch(&self) -> Option<u64> {
        self.next_secrets
            .lock()
            .unwrap()
            .iter()
            .map(|epoch_secret| epoch_secret.key_epoch)
            .max()
    }

    /// Fetch the next set of secrets.
    ///
    /// This will almost always be fetching the secrets for `current_epoch + 2`
    /// unless previous fetches failed. See [epoch_schedule] for more information.
    ///
    /// This function returns the duration until it should be called again. Generally
    /// ~24 hours if the fetch succeeded, or ~1 hour if the fetch failed.
    async fn fetch_secrets(
        &self,
        current_epoch: u64,
        kms_client: &Client,
        failure_notification: &(dyn Fn(anyhow::Error) + Send + Sync + 'static),
    ) -> Result<Duration, Duration> {
        let mut to_fetch = vec![current_epoch, current_epoch + 1, current_epoch + 2];
        let available = self.available_epochs();
        to_fetch.retain(|epoch| !available.contains(epoch));

        for epoch in to_fetch {
            match EpochSecret::fetch_epoch_secret(kms_client, &self.key_arn, epoch).await {
                Ok(epoch_secret) => {
                    tracing::debug!("fetched secret for epoch {epoch} from {}", self.key_arn);
                    self.next_secrets.lock().unwrap().push_back(epoch_secret);
                }
                Err(e) => {
                    tracing::error!(
                        "failed to fetch secret for epoch {epoch} from {}",
                        self.key_arn
                    );
                    failure_notification(e);
                    return Err(ONE_HOUR);
                }
            }
        }

        let sleep = self.newest_available_epoch().and_then(|next_fetch| {
            epoch_schedule::until_fetch(next_fetch + 1, self.smoothing_factor)
        });
        match sleep {
            Some(duration) => Ok(duration),
            None => Err(ONE_HOUR),
        }
    }

    /// Attempt to update the current epoch secret. This should be called at the
    /// start of each epoch.
    ///
    /// Returns the duration until the next orderly rotation should be attempted.
    fn rotate_secrets(&self, current_epoch: u64) -> Duration {
        let needs_rotation = self.current_secret().key_epoch < current_epoch;
        let rotation_key = self
            .next_secrets
            .lock()
            .unwrap()
            .iter()
            .find(|secret| secret.key_epoch == current_epoch)
            .cloned();

        if needs_rotation {
            match rotation_key {
                Some(key) => {
                    tracing::debug!(
                        "current key is now epoch {current_epoch} from {}",
                        self.key_arn
                    );
                    *self.current_secret.write().unwrap() = Arc::new(key);
                }
                None => {
                    tracing::warn!("rotation needed, but the key was not available")
                }
            }
        }

        match epoch_schedule::until_epoch_start(current_epoch + 1) {
            Some(duration) => duration + ROTATION_CUSHION,
            None => {
                // the next epoch has already started. This might be the case if
                // the fetch happened late in the epoch and had high latency.
                Duration::from_secs(0)
            }
        }
    }

    /// Remove old, unused secrets.
    ///
    /// This will not modify [`ProviderSecrets::current_secret`].
    fn drop_old_secrets(&self, current_epoch: u64) {
        self.next_secrets
            .lock()
            .unwrap()
            .retain(|secret| secret.key_epoch > current_epoch);
    }

    // wrapping all of the update logic in this method helps with testability without
    // having to add a generic "clock" parameter.
    async fn poll_update(
        &self,
        current_epoch: u64,
        kms_client: &Client,
        failure_notification: &(dyn Fn(anyhow::Error) + Send + Sync + 'static),
    ) -> Result<Duration, Duration> {
        let until_next_fetch = self
            .fetch_secrets(current_epoch, kms_client, failure_notification)
            .await;
        let until_next_rotation = self.rotate_secrets(current_epoch);
        self.drop_old_secrets(current_epoch);

        match until_next_fetch {
            Ok(until_fetch) => Ok(min(until_fetch, until_next_rotation)),
            Err(until_fetch) => Err(min(until_fetch, until_next_rotation)),
        }
    }
}
#[derive(Debug, Clone)]
pub struct PskProvider {
    secret_state: Arc<ProviderSecrets>,
}

impl PskProvider {
    pub async fn initialize(
        kms_client: Client,
        key_arn: KeyArn,
        failure_notification: impl Fn(anyhow::Error) + Send + Sync + 'static,
    ) -> anyhow::Result<Self> {
        let current_epoch = epoch_schedule::current_epoch();
        let current_secret =
            EpochSecret::fetch_epoch_secret(&kms_client, &key_arn, current_epoch).await?;
        let secret_state = Arc::new(ProviderSecrets {
            key_arn,
            current_secret: RwLock::new(Arc::new(current_secret)),
            next_secrets: Mutex::new(VecDeque::new()),
            smoothing_factor: epoch_schedule::smoothing_factor(),
        });

        let update = secret_state
            .poll_update(current_epoch, &kms_client, &failure_notification)
            .await;
        if update.is_err() {
            anyhow::bail!("failed to fetch keys during startup");
        }

        tokio::task::spawn({
            let secret_state = Arc::clone(&secret_state);
            async move {
                loop {
                    let current_epoch = epoch_schedule::current_epoch();

                    let sleep_duration = secret_state
                        .poll_update(current_epoch, &kms_client, &failure_notification)
                        .await;
                    let sleep_duration = match sleep_duration {
                        Ok(duration) => duration,
                        Err(duration) => duration,
                    };
                    tracing::debug!("sleeping for {sleep_duration:?}");
                    tokio::time::sleep(sleep_duration).await;
                }
            }
        });
        Ok(Self { secret_state })
    }
}

impl ConnectionInitializer for PskProvider {
    fn initialize_connection(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
        let psk = self.secret_state.current_secret().new_connection_psk()?;
        connection.append_psk(&psk)?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        configs_from_callbacks, handshake, mocked_kms_client, PskIdentityObserver, KMS_KEY_ARN_A,
    };
    use aws_sdk_kms::{
        operation::generate_mac::{GenerateMacError, GenerateMacOutput},
        primitives::Blob,
        Client,
    };
    use aws_smithy_mocks::{mock, mock_client, RuleMode};
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    /// The session names for each connection should be unique
    #[tokio::test]
    async fn session_names_are_random() {
        let psk_provider =
            PskProvider::initialize(mocked_kms_client(), KMS_KEY_ARN_A.to_owned(), |_| {})
                .await
                .unwrap();
        let psk_capturer = PskIdentityObserver::default();
        let observer_handle = psk_capturer.clone();
        let (client_config, server_config) = configs_from_callbacks(psk_provider, psk_capturer);

        handshake(&client_config, &server_config).await.unwrap_err();
        handshake(&client_config, &server_config).await.unwrap_err();

        let observed_psks = observer_handle.0.lock().unwrap().clone();
        assert!(observed_psks[1].key_epoch - observed_psks[0].key_epoch <= 1);
        assert!(observed_psks[1].session_name != observed_psks[0].session_name);
    }

    #[tokio::test]
    async fn poll_update() -> Result<(), Duration> {
        let psk_provider =
            PskProvider::initialize(mocked_kms_client(), KMS_KEY_ARN_A.to_owned(), |_| {})
                .await
                .unwrap();
        let mut this_epoch = epoch_schedule::current_epoch();
        let client = mocked_kms_client();
        let secret_state = psk_provider.secret_state;

        // call poll update to get our initial state for "this_epoch"
        secret_state
            .poll_update(this_epoch, &client, &|_| {})
            .await?;
        let available = secret_state.available_epochs();
        assert_eq!(available.len(), 3);
        assert!(available.contains(&this_epoch));
        assert!(available.contains(&(this_epoch + 1)));
        assert!(available.contains(&(this_epoch + 2)));
        let current_epoch_secret = secret_state.current_secret();

        // a second call should be idempotent, no time has passed
        secret_state
            .poll_update(this_epoch, &client, &|_| {})
            .await?;
        assert_eq!(secret_state.available_epochs(), available);
        assert_eq!(secret_state.current_secret(), current_epoch_secret);
        let oldest = *available.iter().min().unwrap();

        // when time advances, we
        // 1. fetch a new secret
        // 2. rotate the current one
        // 3. drop the old one
        this_epoch += 1;
        secret_state
            .poll_update(this_epoch, &client, &|_| {})
            .await?;
        assert_eq!(secret_state.available_epochs().len(), available.len());
        assert!(secret_state
            .available_epochs()
            .into_iter()
            .all(|epoch| epoch != oldest));
        assert!(secret_state.available_epochs().contains(&(this_epoch + 2)));
        assert_eq!(secret_state.current_secret().key_epoch, this_epoch);

        // time skips are gracefully handled
        this_epoch += 2;
        secret_state
            .poll_update(this_epoch, &client, &|_| {})
            .await?;
        assert_eq!(secret_state.available_epochs().len(), 3);
        assert!(secret_state.available_epochs().contains(&this_epoch));
        assert!(secret_state.available_epochs().contains(&(this_epoch + 1)));
        assert!(secret_state.available_epochs().contains(&(this_epoch + 2)));
        assert_eq!(secret_state.current_secret().key_epoch, this_epoch);

        Ok(())
    }

    #[tokio::test]
    async fn provider_initialization_when_kms_fetch_fails() {
        let fail_rule = mock!(Client::generate_mac).then_error(|| {
            aws_sdk_kms::operation::generate_mac::GenerateMacError::unhandled("MockedFailure")
        });

        let kms_client = mock_client!(aws_sdk_kms, RuleMode::MatchAny, [&fail_rule]);

        let error = PskProvider::initialize(kms_client, KMS_KEY_ARN_A.to_owned(), |_| {})
            .await
            .unwrap_err();

        assert_eq!(error.to_string(), "service error");
    }

    #[tokio::test]
    async fn poll_update_with_failure() {
        let error_count = Arc::new(AtomicUsize::new(0));
        let notification_fn = {
            let error_count = Arc::clone(&error_count);
            move |_: anyhow::Error| {
                error_count.fetch_add(1, Ordering::SeqCst);
            }
        };

        let rule = mock!(Client::generate_mac)
            .sequence()
            .output(|| {
                GenerateMacOutput::builder()
                    .mac(Blob::new(b"mock_mac_output".to_vec()))
                    .build()
            })
            .times(4)
            .error(|| GenerateMacError::unhandled("MockedFailure"))
            .times(4)
            .build();
        let kms_client = mock_client!(aws_sdk_kms, [&rule]);

        // we successfully initialize, resulting in 3 KMS calls
        let psk_provider = PskProvider::initialize(
            kms_client.clone(),
            KMS_KEY_ARN_A.to_owned(),
            notification_fn.clone(),
        )
        .await
        .unwrap();
        assert_eq!(rule.num_calls(), 3);
        let mut current_epoch = epoch_schedule::current_epoch();

        // we successfully fetch the secret, the error count should be 0
        current_epoch += 1;
        psk_provider
            .secret_state
            .poll_update(current_epoch, &kms_client, &notification_fn)
            .await
            .unwrap();
        assert_eq!(error_count.load(Ordering::SeqCst), 0);
        assert_eq!(
            psk_provider.secret_state.available_epochs(),
            vec![current_epoch, current_epoch + 1, current_epoch + 2]
        );
        assert_eq!(
            psk_provider
                .secret_state
                .current_secret
                .read()
                .unwrap()
                .key_epoch,
            current_epoch
        );

        // we fail to fetch the secret, the error count should be 1
        current_epoch += 1;
        psk_provider
            .secret_state
            .poll_update(current_epoch, &kms_client, &notification_fn)
            .await
            .unwrap_err();
        assert_eq!(error_count.load(Ordering::SeqCst), 1);
        assert_eq!(rule.num_calls(), 5);
        // we failed to fetch the latest secret
        assert_eq!(
            psk_provider.secret_state.available_epochs(),
            vec![current_epoch, current_epoch + 1]
        );
        assert_eq!(
            psk_provider
                .secret_state
                .current_secret
                .read()
                .unwrap()
                .key_epoch,
            current_epoch
        );

        // The cases below assert that when we fail to fetch new secrets, a best
        // effort is made using the last secret we fetched.
        current_epoch += 1;
        psk_provider
            .secret_state
            .poll_update(current_epoch, &kms_client, &notification_fn)
            .await
            .unwrap_err();
        assert_eq!(
            psk_provider.secret_state.available_epochs(),
            vec![current_epoch]
        );
        assert_eq!(
            psk_provider
                .secret_state
                .current_secret
                .read()
                .unwrap()
                .key_epoch,
            current_epoch
        );

        current_epoch += 1;
        psk_provider
            .secret_state
            .poll_update(current_epoch, &kms_client, &notification_fn)
            .await
            .unwrap_err();
        assert_eq!(
            psk_provider.secret_state.available_epochs(),
            vec![current_epoch - 1]
        );
        assert_eq!(
            psk_provider
                .secret_state
                .current_secret
                .read()
                .unwrap()
                .key_epoch,
            current_epoch - 1
        );

        current_epoch += 1;
        psk_provider
            .secret_state
            .poll_update(current_epoch, &kms_client, &notification_fn)
            .await
            .unwrap_err();
        assert_eq!(
            psk_provider.secret_state.available_epochs(),
            vec![current_epoch - 2]
        );
        assert_eq!(
            psk_provider
                .secret_state
                .current_secret
                .read()
                .unwrap()
                .key_epoch,
            current_epoch - 2
        );
    }
}
