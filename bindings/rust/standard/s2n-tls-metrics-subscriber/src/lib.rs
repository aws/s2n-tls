// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod compatibility;
pub(crate) mod counter;
pub mod detector;
#[cfg(feature = "fuzzing")]
pub mod parsing;
#[cfg(not(feature = "fuzzing"))]
mod parsing;
mod record;
pub mod subscriber;
pub mod telemetry_sink;
#[cfg(test)]
mod test_utils;

pub use detector::SyntheticTrafficDetector;
pub use subscriber::AggregatedMetricsSubscriber;
pub use telemetry_sink::TelemetrySink;

/// Identifies the source of a metric record by service and resource.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Attribution {
    /// The service or application name (e.g. "my-tls-service")
    pub service: String,
    /// The resource producing metrics (e.g. an ARN or listener name)
    pub resource: String,
    /// Distinguishes telemetry from multiple components within the same
    /// application.
    pub component: String,
}

impl Attribution {
    pub(crate) fn into_schema(self) -> s2n_tls_metrics_schema::attribution::Attribution {
        s2n_tls_metrics_schema::attribution::Attribution {
            service: self.service,
            resource: self.resource,
            component: self.component,
        }
    }
}

/// Opaque metric record produced by [`AggregatedMetricsSubscriber`].
///
/// This type implements `serde::Serialize` and `metrique_writer::Entry` so
/// that [`TelemetrySink`] implementations can serialize it in any format
/// without depending on the internal schema types.
///
/// For field-level inspection, consumers should depend on
/// `s2n-tls-metrics-schema` directly and deserialize from the serialized
/// bytes. That crate carries no stability guarantees.
#[derive(Debug, Clone)]
pub struct MetricRecord(s2n_tls_metrics_schema::record::MetricRecord);

impl MetricRecord {
    pub(crate) fn new(inner: s2n_tls_metrics_schema::record::MetricRecord) -> Self {
        Self(inner)
    }

    #[cfg(test)]
    pub(crate) fn as_schema(&self) -> &s2n_tls_metrics_schema::record::MetricRecord {
        &self.0
    }
}

impl serde::Serialize for MetricRecord {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl metrique_writer::Entry for MetricRecord {
    fn write<'a>(&'a self, writer: &mut impl metrique_writer::EntryWriter<'a>) {
        self.0.write(writer)
    }
}
