// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    sync::{
        Arc, Condvar, Mutex,
        mpsc::{self, Receiver, Sender},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::record::{FrozenHandshakeRecord, HandshakeRecordInProgress, MetricRecord};
use arc_swap::ArcSwap;
use s2n_tls::events::EventSubscriber;

#[derive(Debug)]
struct ExportPipeline<E> {
    metric_receiver: Receiver<FrozenHandshakeRecord>,
    exporter: E,
}

/// The AggregatedMetricSubscriber can be used to aggregate events over some period
/// of time, and then export them using an [`Exporter`].
#[derive(Debug)]
pub struct AggregatedMetricsSubscriber<E> {
    inner: Arc<MetricSubscriberInner<E>>,
}

// Manual Clone impl: the derive would add an unnecessary `E: Clone` bound,
// but we only need to clone the Arc.
impl<E> Clone for AggregatedMetricsSubscriber<E> {
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
struct MetricSubscriberInner<E> {
    current_record: ArcSwap<HandshakeRecordInProgress>,
    /// This handle is not directly used, but is used when constructing new
    /// HandshakeRecordInProgress items.
    tx_handle: Sender<FrozenHandshakeRecord>,

    // the mutex is necessary because s2n-tls callbacks must be Send + Sync
    export_pipeline: Mutex<ExportPipeline<E>>,

    /// Optional resource name associated with this subscriber.
    resource_name: Option<Arc<str>>,
}

impl<E: Exporter + Send + Sync> AggregatedMetricsSubscriber<E> {
    pub fn new(exporter: E) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();

        let record = HandshakeRecordInProgress::new(tx.clone());

        let export_pipe = ExportPipeline {
            metric_receiver: rx,
            exporter,
        };
        let inner = MetricSubscriberInner {
            current_record: ArcSwap::new(Arc::new(record)),
            tx_handle: tx,
            export_pipeline: Mutex::new(export_pipe),
            resource_name: None,
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Create a new subscriber with an associated resource name.
    ///
    /// The resource name will be included in all exported [`MetricRecord`]s,
    /// allowing metrics to be tagged per-resource.
    pub fn with_resource_name(exporter: E, resource_name: impl Into<Arc<str>>) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();

        let record = HandshakeRecordInProgress::new(tx.clone());

        let export_pipe = ExportPipeline {
            metric_receiver: rx,
            exporter,
        };
        let inner = MetricSubscriberInner {
            current_record: ArcSwap::new(Arc::new(record)),
            tx_handle: tx,
            export_pipeline: Mutex::new(export_pipe),
            resource_name: Some(resource_name.into()),
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
        export_pipeline.exporter.export(MetricRecord::new(
            handshake,
            self.inner.resource_name.clone(),
        ));
    }
}

impl<E: Send + Sync + 'static> EventSubscriber for AggregatedMetricsSubscriber<E> {
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

pub trait Exporter {
    /// export a record to some sink.
    ///
    /// This might append it to some background IO (e.g. tracing_subscriber) or
    /// directly buffer content to be further processed (e.g. converted to EMF).
    fn export(&self, metric_record: MetricRecord);
}

impl Exporter for mpsc::Sender<MetricRecord> {
    fn export(&self, metric_record: MetricRecord) {
        self.send(metric_record).unwrap()
    }
}

/// Handle for a periodic export background thread.
///
/// When dropped, signals the background thread to stop, performs a final
/// `finish_record()` call, and joins the thread.
pub struct PeriodicExportHandle<E: Exporter + Send + Sync + 'static> {
    stop: Arc<(Mutex<bool>, Condvar)>,
    handle: Option<JoinHandle<()>>,
    subscriber: AggregatedMetricsSubscriber<E>,
}

impl<E: Exporter + Send + Sync + 'static> AggregatedMetricsSubscriber<E> {
    /// Start a background thread that calls `finish_record()` at the given interval.
    ///
    /// Returns a [`PeriodicExportHandle`] that stops the background thread and
    /// performs a final export when dropped.
    pub fn start_periodic_export(&self, interval: Duration) -> PeriodicExportHandle<E> {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let stop_clone = stop.clone();
        let subscriber = self.clone();

        // Use a Condvar so Drop can wake the worker promptly instead of
        // waiting for the full interval to elapse.
        let handle = thread::spawn(move || {
            let (lock, cvar) = &*stop_clone;
            loop {
                let guard = lock.lock().unwrap();
                if *guard {
                    break;
                }
                // Wait for the interval or until signaled to stop.
                let (guard, _) = cvar.wait_timeout(guard, interval).unwrap();
                if *guard {
                    break;
                }
                drop(guard);
                subscriber.finish_record();
            }
        });

        PeriodicExportHandle {
            stop,
            handle: Some(handle),
            subscriber: self.clone(),
        }
    }
}

impl<E: Exporter + Send + Sync + 'static> Drop for PeriodicExportHandle<E> {
    fn drop(&mut self) {
        {
            let (lock, cvar) = &*self.stop;
            let mut stopped = lock.lock().unwrap();
            *stopped = true;
            cvar.notify_one();
        }
        if let Some(handle) = self.handle.take() {
            handle.join().ok();
        }
        // Perform one final synchronous flush so metrics accumulated since
        // the last interval are not lost during shutdown.
        self.subscriber.finish_record();
    }
}

#[cfg(test)]
mod tests {

    use crate::test_utils::{ARBITRARY_POLICY_1, TestEndpoint};

    #[test]
    fn record_is_exported() {
        let endpoint = TestEndpoint::new();
        endpoint.client_handshake(&ARBITRARY_POLICY_1);

        assert!(endpoint.exporter.try_recv().is_err());
        endpoint.subscriber.finish_record();
        endpoint.exporter.recv().unwrap();
    }

    /// Ensure that the `finish_record` method won't complete until no other threads
    /// hold a reference to the record-in-progress.
    ///
    /// This test could have a "false negative", e.g. it might succeed even if the
    /// system isn't operating correctly, but this is acceptable given the relative
    /// simplicity of the synchronization, as well as the repeated runs of this
    /// test across CI/development.
    #[test]
    fn export_blocking() {
        let endpoint = TestEndpoint::new();
        endpoint.client_handshake(&ARBITRARY_POLICY_1);

        // hold a reference to the current record being updated.
        let current_record = endpoint.subscriber.inner.current_record.load_full();

        let handle = std::thread::spawn(move || {
            endpoint.subscriber.finish_record();
        });

        assert!(!handle.is_finished());
        drop(current_record);
        handle.join().unwrap();
    }

    #[test]
    fn periodic_export_produces_record() {
        let endpoint = TestEndpoint::new();
        endpoint.client_handshake(&ARBITRARY_POLICY_1);

        let _handle = endpoint
            .subscriber
            .start_periodic_export(std::time::Duration::from_millis(50));

        // Block until a record arrives, with a generous timeout to avoid
        // flakiness under CI load.
        endpoint
            .exporter
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("periodic export should have produced a record");
    }

    #[test]
    fn periodic_export_drop_produces_final_record() {
        let endpoint = TestEndpoint::new();
        endpoint.client_handshake(&ARBITRARY_POLICY_1);

        // Use a long interval so the background thread won't fire on its own
        let handle = endpoint
            .subscriber
            .start_periodic_export(std::time::Duration::from_secs(60));

        // Drop the handle — this should trigger a final finish_record()
        drop(handle);

        // The final export from Drop should have produced a record
        assert!(endpoint.exporter.try_recv().is_ok());
    }
}
