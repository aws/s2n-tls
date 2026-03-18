// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};

/// Trait abstracting the write destination for EMF records.
pub trait EmfSink: Send + Sync + 'static {
    fn write_record(&self, record: &[u8]) -> io::Result<()>;
}

/// Writes EMF records to stdout.
pub struct StdoutSink;

impl EmfSink for StdoutSink {
    fn write_record(&self, record: &[u8]) -> io::Result<()> {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        handle.write_all(record)?;
        handle.write_all(b"\n")?;
        handle.flush()
    }
}

/// Writes EMF records to any `Write` implementor, protected by a `Mutex`.
pub struct WriterSink<W: Write + Send + 'static> {
    writer: Mutex<W>,
}

impl<W: Write + Send + 'static> WriterSink<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
        }
    }
}

impl<W: Write + Send + 'static> EmfSink for WriterSink<W> {
    fn write_record(&self, record: &[u8]) -> io::Result<()> {
        let mut writer = self
            .writer
            .lock()
            .map_err(|e| io::Error::other(format!("lock poisoned: {}", e)))?;
        writer.write_all(record)?;
        writer.write_all(b"\n")?;
        writer.flush()
    }
}

impl<T: EmfSink> EmfSink for Arc<T> {
    fn write_record(&self, record: &[u8]) -> io::Result<()> {
        (**self).write_record(record)
    }
}
