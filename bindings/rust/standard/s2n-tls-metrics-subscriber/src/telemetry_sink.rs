// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{io, sync::Arc};

/// Trait abstracting the write destination for serialized metric records.
///
/// Implementations receive raw bytes (a complete serialized `MetricRecord`
/// in the format configured on the subscriber) and write them to a
/// destination such as stdout, a file, or a network socket.
pub trait TelemetrySink: Send + Sync + 'static {
    /// Write a single serialized metric record.
    fn write_record(&self, record: &[u8]) -> io::Result<()>;
}

impl<T: TelemetrySink> TelemetrySink for Arc<T> {
    fn write_record(&self, record: &[u8]) -> io::Result<()> {
        (**self).write_record(record)
    }
}
