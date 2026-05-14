// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod attribution;
mod compatibility;
pub mod counter;
mod label;
#[cfg(feature = "fuzzing")]
pub mod parsing;
#[cfg(not(feature = "fuzzing"))]
mod parsing;
mod record;
pub mod static_lists;
pub mod subscriber;
pub mod telemetry_sink;
#[cfg(test)]
mod test_utils;

pub use attribution::Attribution;
pub use counter::FrozenCounter;
pub use record::{FrozenHandshakeRecord, MetricRecord};
pub use static_lists::{
    CIPHER_COUNT, Cipher, FiniteCounter, GROUP_COUNT, Group, PROTOCOL_COUNT, SIGNATURE_COUNT,
    Signature, Version,
};
pub use subscriber::AggregatedMetricsSubscriber;
pub use telemetry_sink::TelemetrySink;
