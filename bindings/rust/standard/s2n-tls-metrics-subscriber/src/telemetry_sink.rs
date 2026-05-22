// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::record::MetricRecord;

/// Trait abstracting the export destination for metric records.
///
/// Implementations receive a [`MetricRecord`] and are responsible for
/// serializing it in whatever format they prefer (JSON, CBOR, EMF, etc.)
/// and writing it to a destination such as stdout, a file, or a network
/// socket.
///
/// `MetricRecord` implements both `serde::Serialize` and
/// `metrique_writer::Entry`, so sinks can choose between serde-based
/// formats (JSON via `serde_json`, CBOR via `ciborium`, etc.) or the
/// metrique writer pipeline.
pub trait TelemetrySink: Send + Sync + 'static {
    /// Export a single metric record.
    fn export_record(&self, record: &MetricRecord);
}

/// Blanket impl so that callers can pass an `Arc<T>` directly as a sink.
/// This is useful when the caller wants to share a single sink instance
/// across multiple subscribers — they wrap it in an `Arc` and pass clones
/// without the underlying sink type needing to implement `Clone`.
impl<T: TelemetrySink> TelemetrySink for Arc<T> {
    fn export_record(&self, record: &MetricRecord) {
        (**self).export_record(record)
    }
}
