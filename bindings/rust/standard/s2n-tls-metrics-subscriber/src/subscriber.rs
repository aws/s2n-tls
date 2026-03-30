// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::attribution::Attribution;
use crate::format::SerializationFormat;
use crate::record::{FrozenHandshakeRecord, HandshakeRecordInProgress, MetricRecord};
use crate::sink::Sink;
use arc_swap::ArcSwap;
use s2n_tls::events::EventSubscriber;
use std::sync::{
    Arc, Condvar, Mutex,
    mpsc::{self, Receiver, Sender},
};
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Debug)]
struct ExportPipeline<S: Sink> {
    metric_receiver: Receiver<FrozenHandshakeRecord>,
    sink: S,
    format: SerializationFormat,
}

/// The AggregatedMetricSubscriber can be used to aggregate events over some period
/// of time, and then export them using a [`Sink`].
#[derive(Debug)]
pub struct AggregatedMetricsSubscriber<S: Sink> {
    pub(crate) inner: Arc<MetricSubscriberInner<S>>,
}

impl<S: Sink> Clone for AggregatedMetricsSubscriber<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// The [`s2n_tls::events::EventSubscriber`] may be invoked concurrently, which
/// means that multiple threads might be incrementing the current record. To handle
/// this and ensure that the `HandshakeRecordInProgress` is never flushed while
/// an update is in progress we use an [`arc_swap::ArcSwap`].
///
/// ArcSwap is basically an `Atomic<Arc<HandshakeRecordInProgress>>`
///
/// We use this as a relatively intuitive form of synchronization. Once there
/// are no references to the HandshakeRecordInProgress (e.g. no threads updating
/// it) then its `drop` implementation will write it to the channel, where it can
/// then be read by the export pipeline.
#[derive(Debug)]
pub(crate) struct MetricSubscriberInner<S: Sink> {
    pub(crate) current_record: ArcSwap<HandshakeRecordInProgress>,
    /// This handle is not directly used, but is used when constructing new
    /// HandshakeRecordInProgress items.
    tx_handle: Sender<FrozenHandshakeRecord>,

    // the mutex is necessary because s2n-tls callbacks must be Send + Sync
    export_pipeline: Mutex<ExportPipeline<S>>,
    attribution: Attribution,
}

impl<S: Sink> AggregatedMetricsSubscriber<S> {
    pub fn new(sink: S, format: SerializationFormat, attribution: Attribution) -> Self {
        let (tx, rx) = mpsc::channel();

        let record = HandshakeRecordInProgress::new(tx.clone());

        let export_pipe = ExportPipeline {
            metric_receiver: rx,
            sink,
            format,
        };
        let inner = MetricSubscriberInner {
            current_record: ArcSwap::new(Arc::new(record)),
            tx_handle: tx,
            export_pipeline: Mutex::new(export_pipe),
            attribution,
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Finish aggregation of the record and export it.
    ///
    /// Note that this method will block until all other in-flight updates of the
    /// metric record are complete. This is generally very fast because updates
    /// only consist of atomic integer updates, but latency-sensitive applications
    /// should avoid calling this method in a tokio runtime, and using `spawn_blocking`
    /// instead.
    pub fn finish_record(&self) {
        let export_pipeline = self.inner.export_pipeline.lock().unwrap();
        let new_record = Arc::new(HandshakeRecordInProgress::new(self.inner.tx_handle.clone()));

        let old_record = self.inner.current_record.swap(new_record);
        // On drop, the record will be "frozen" and written to the channel
        // This might not happen immediately because other threads might also hold
        // a reference to the metric record
        drop(old_record);

        // This will block the thread until the record is received.
        let handshake = export_pipeline.metric_receiver.recv().unwrap();
        let record = MetricRecord::new(handshake, self.inner.attribution.clone());
        match export_pipeline.format.serialize(&record) {
            Ok(bytes) => {
                if let Err(e) = export_pipeline.sink.write_record(&bytes) {
                    tracing::error!("failed to write metric to sink: {e}");
                }
            }
            Err(e) => {
                tracing::error!("failed to serialize metric record: {e}");
            }
        }
    }
}

impl<S: Sink> EventSubscriber for AggregatedMetricsSubscriber<S> {
    fn on_handshake_event(
        &self,
        connection: &s2n_tls::connection::Connection,
        event: &s2n_tls::events::HandshakeEvent,
    ) {
        let current_record = self.inner.current_record.load_full();
        let res = current_record.update(connection, event);
        // we never expect this to fail, but if it fails in production there is
        // no meaningful way to handle the failure
        debug_assert!(res.is_ok());
        if let Err(e) = res {
            tracing::error!("failed to update handshake record: {e}");
        }
    }
}

/// A handle to a background thread that periodically calls `finish_record()`
/// on the associated subscriber.
///
/// When dropped, the handle signals the background thread to stop, joins it,
/// and performs a final `finish_record()` call to flush any accumulated metrics.
pub struct PeriodicExportHandle<S: Sink> {
    subscriber: AggregatedMetricsSubscriber<S>,
    stop: Arc<(Mutex<bool>, Condvar)>,
    handle: Option<JoinHandle<()>>,
}

impl<S: Sink> AggregatedMetricsSubscriber<S> {
    /// Start a background thread that calls `finish_record()` at the given interval.
    ///
    /// The returned handle must be kept alive for the periodic export to continue.
    /// Dropping the handle stops the background thread and performs a final flush.
    pub fn start_periodic_export(&self, interval: Duration) -> PeriodicExportHandle<S> {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let stop_clone = stop.clone();
        let subscriber = self.clone();
        let handle = std::thread::spawn(move || {
            let (lock, cvar) = &*stop_clone;
            loop {
                let guard = lock.lock().unwrap();
                let result = cvar.wait_timeout(guard, interval).unwrap();
                if *result.0 {
                    break;
                }
                drop(result);
                subscriber.finish_record();
            }
        });
        PeriodicExportHandle {
            subscriber: self.clone(),
            stop,
            handle: Some(handle),
        }
    }

    /// Start periodic export with the default interval of one hour.
    pub fn start_periodic_export_default(&self) -> PeriodicExportHandle<S> {
        self.start_periodic_export(Duration::from_secs(3600))
    }
}

impl<S: Sink> Drop for PeriodicExportHandle<S> {
    fn drop(&mut self) {
        let (lock, cvar) = &*self.stop;
        *lock.lock().unwrap() = true;
        cvar.notify_one();
        if let Some(handle) = self.handle.take() {
            handle.join().ok();
        }
        self.subscriber.finish_record();
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{ARBITRARY_POLICY_1, TestEndpoint};

    /// Verify that after a handshake and finish_record, the sink contains a record.
    #[test]
    fn record_is_exported() {
        let endpoint = TestEndpoint::new();

        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();

        let records = endpoint.sink.records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert!(!records[0].is_empty());
    }

    /// Verify that finish_record blocks while another thread holds a reference
    /// to the current record (via ArcSwap load_full).
    #[test]
    fn export_blocking() {
        let endpoint = TestEndpoint::new();

        endpoint.client_handshake(&ARBITRARY_POLICY_1);

        // Load a reference to the current record, preventing it from being dropped
        let held_record = endpoint.subscriber.inner.current_record.load_full();

        let subscriber = endpoint.subscriber.clone();
        let handle = std::thread::spawn(move || {
            subscriber.finish_record();
        });

        // The finish_record call should be blocked because we hold a reference
        // Give it a moment to ensure it's actually blocked
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            !handle.is_finished(),
            "finish_record should block while record reference is held"
        );

        // Drop the held reference to unblock finish_record
        drop(held_record);
        handle.join().unwrap();

        let records = endpoint.sink.records.lock().unwrap();
        assert_eq!(records.len(), 1);
    }
}
