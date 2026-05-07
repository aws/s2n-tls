// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod attribution;
mod compatibility;
mod label;
#[cfg(feature = "fuzzing")]
pub mod parsing;
#[cfg(not(feature = "fuzzing"))]
mod parsing;
mod record;
mod static_lists;
pub mod subscriber;
pub mod telemetry_sink;
#[cfg(test)]
mod test_utils;

pub use attribution::Attribution;
pub use record::MetricRecord;
pub use subscriber::AggregatedMetricsSubscriber;
pub use telemetry_sink::TelemetrySink;
