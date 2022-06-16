// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::callbacks::MonotonicClockCallback;
use std::time::Duration;
use tokio::time::Instant;

/// A monotonic clock that allows the s2n-tls C library time
/// to follow the tokio::time::pause behavior.
pub struct TokioTime(Instant);

impl Default for TokioTime {
    fn default() -> Self {
        TokioTime(Instant::now())
    }
}

impl MonotonicClockCallback for TokioTime {
    fn get_time(&self) -> Duration {
        self.0.elapsed()
    }
}
