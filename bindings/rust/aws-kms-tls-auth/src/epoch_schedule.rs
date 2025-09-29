// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The key epochs and fetching behavior are designed to accomplish the following
//! goals:
//! Requirement 1: if fetching new keys fails, there should be at least 24 hours before
//! handshakes actually start failing.
//! Requirement 2: traffic to KMS should be smooth, avoiding any spikes at e.g.
//! the top of the hour.
//!
//! ```text
//! Epoch
//! 0     1     2     3     4
//! |-----|-----|-----|-----|
//!                   ^
//!                   epoch 3 start
//!```
//!
//! To satisfy these requirements, we fetch the key for epoch `n` during epoch
//! `n - 2`. Each peer adds [0, 24 * 3600) seconds of delay to smooth out traffic
//! to KMS. This is referred to as a "smoothing factor".
//!
//! ```text
//! Epoch
//! 0     1     2     3     4
//! |-----|-----|-----|-----|
//!       ++++++      ^
//!          ^        epoch 3 start
//!          |
//!        fetch window for epoch 3   
//! ```

use rand::Rng;
use std::time::{Duration, SystemTime};

/// The epoch duration controls how long an epoch secret is used for.
pub(crate) const EPOCH_DURATION: Duration = Duration::from_secs(3_600 * 24);

/// Return a "smoothing factor" indicating how long the actor should wait before
/// fetching the key for some epoch
pub fn smoothing_factor() -> Duration {
    rand::rng().random_range(Duration::from_secs(0)..EPOCH_DURATION)
}

pub fn current_epoch() -> u64 {
    // SAFETY: this method will panic if the current system clock is set to
    // a time before the unix epoch. This is not a recoverable error, so we
    // panic
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("expected system time to be after UNIX epoch");
    now.as_secs() / (EPOCH_DURATION.as_secs())
}

/// Return the instant in time that `epoch` starts
pub fn epoch_start(epoch: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + (EPOCH_DURATION * (epoch as u32))
}

/// The Duration between now and the start of epoch
///
/// returns None if the epoch has already started
pub fn until_epoch_start(epoch: u64) -> Option<Duration> {
    epoch_start(epoch).duration_since(SystemTime::now()).ok()
}

/// The Duration between now and when the actor should make the network call
/// to KMS to retrieve the secret for `epoch`.
///
/// returns None if the fetch should already have occurred
pub(crate) fn until_fetch(epoch: u64, smoothing_factor: Duration) -> Option<Duration> {
    // we always want to fetch the key at least one epoch (24 hours) before the
    // key is needed.
    let fetch_time = {
        let fetch_epoch = epoch - 2;

        let fetch_epoch_start = epoch_start(fetch_epoch);

        fetch_epoch_start + smoothing_factor
    };

    fetch_time.duration_since(SystemTime::now()).ok()
}

// Note that these tests technically have a "race condition". We assume that
// "current_epoch + 1" is in the future, but if the test is started right before the
// epoch boundary that might not be true.
//
// However the failure rate is approximately 1/ 3,200,000,000 for these tests, so
// the simpler approach is worth the theoretical risk.
// Flakiness Probability:
//     test runtime: 27.48 us -> unit test runtime, window of "flaky"
//     probability = 27.48 us / 24 hr
//     approximately 1 / 3_200_000_000
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current() {
        let current_epoch = current_epoch();
        let start = epoch_start(current_epoch);
        assert!(SystemTime::now().duration_since(start).is_ok());
        let future_start = epoch_start(current_epoch + 1);
        assert!(future_start.duration_since(SystemTime::now()).is_ok());
    }

    #[test]
    fn until_start() {
        let current = current_epoch();
        // epoch start was in the past, and should return none
        assert!(until_epoch_start(current).is_none());
        assert!(until_epoch_start(current + 1).is_some());
    }

    #[test]
    fn fetch() {
        const ZERO_DURATION: Duration = Duration::from_secs(0);

        let current_epoch = current_epoch();
        assert!(until_fetch(current_epoch, ZERO_DURATION).is_none());
        assert!(until_fetch(current_epoch + 1, ZERO_DURATION).is_none());
        assert!(until_fetch(current_epoch + 2, ZERO_DURATION).is_none());
        assert!(until_fetch(current_epoch + 2, EPOCH_DURATION).is_some());
    }

    #[test]
    fn smoothing_factor() {
        for _ in 0..10 {
            assert!(super::smoothing_factor() < EPOCH_DURATION);
        }
    }
}
