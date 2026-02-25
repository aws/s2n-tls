// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{
    mpsc::{self, Receiver, Sender},
    Arc, Mutex,
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
#[derive(Debug, Clone)]
pub struct AggregatedMetricsSubscriber<E> {
    inner: Arc<MetricSubscriberInner<E>>,
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
        export_pipeline
            .exporter
            .export(MetricRecord::new(handshake));
    }
}

impl<E: Send + Sync + 'static> EventSubscriber for AggregatedMetricsSubscriber<E> {
    fn on_handshake_event(
        &self,
        connection: &s2n_tls::connection::Connection,
        event: &s2n_tls::events::HandshakeEvent,
    ) {
        let current_record = self.inner.current_record.load_full();
        current_record.update(connection, event);
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

#[cfg(test)]
mod tests {

    use std::sync::mpsc::Receiver;

    use crate::{
        test_utils::{TestEndpoint, ARBITRARY_POLICY_1},
        MetricRecord,
    };

    #[test]
    fn record_is_exported() {
        let endpoint = TestEndpoint::<Receiver<MetricRecord>>::new();
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
        let endpoint = TestEndpoint::<Receiver<MetricRecord>>::new();
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
}
