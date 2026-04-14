// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    attribution::Attribution,
    record::{FrozenHandshakeRecord, HandshakeRecordInProgress, MetricRecord},
    telemetry_sink::TelemetrySink,
};
use arc_swap::ArcSwap;
use s2n_tls::events::EventSubscriber;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    time::{Duration, SystemTime},
};

#[derive(Debug)]
struct ExportPipeline<S: TelemetrySink> {
    metric_receiver: Receiver<FrozenHandshakeRecord>,
    sink: S,
}

/// The AggregatedMetricSubscriber can be used to aggregate events over some period
/// of time, and then export them using a [`TelemetrySink`].
#[derive(Debug, Clone)]
pub struct AggregatedMetricsSubscriber<S: TelemetrySink> {
    inner: Arc<MetricSubscriberInner<S>>,
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
struct MetricSubscriberInner<S: TelemetrySink> {
    current_record: ArcSwap<HandshakeRecordInProgress>,
    /// This handle is not directly used, but is used when constructing new
    /// HandshakeRecordInProgress items.
    tx_handle: Sender<FrozenHandshakeRecord>,

    // the mutex is necessary because s2n-tls callbacks must be Send + Sync
    export_pipeline: Mutex<ExportPipeline<S>>,
    attribution: Attribution,

    /// If set, the subscriber will passively export the record when at least
    /// this much time has elapsed since the last export. The check happens
    /// inside `on_handshake_event`, so export is piggy-backed on handshake
    /// traffic rather than requiring a background thread.
    export_interval: Option<Duration>,
    /// Epoch millis of the last successful export (or construction time).
    /// Using an AtomicU64 so the fast-path check in `on_handshake_event`
    /// doesn't need to acquire the export_pipeline mutex.
    last_export_epoch_ms: AtomicU64,
}

fn epoch_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl<S: TelemetrySink> AggregatedMetricsSubscriber<S> {
    pub fn new(sink: S, attribution: Attribution) -> Self {
        Self::build(sink, attribution, None)
    }

    /// Create a subscriber that passively exports the aggregated record
    /// whenever at least `interval` has elapsed since the last export.
    ///
    /// The check is performed inside `on_handshake_event`, so no background
    /// thread is needed — export is driven by handshake traffic. If there
    /// are no handshakes for a long period, no export will occur until the
    /// next handshake (or an explicit `finish_record()` call).
    pub fn with_periodic_export(sink: S, attribution: Attribution, interval: Duration) -> Self {
        Self::build(sink, attribution, Some(interval))
    }

    fn build(sink: S, attribution: Attribution, export_interval: Option<Duration>) -> Self {
        let (tx, rx) = mpsc::channel();

        let record = HandshakeRecordInProgress::new(tx.clone());

        let export_pipe = ExportPipeline {
            metric_receiver: rx,
            sink,
        };
        let inner = MetricSubscriberInner {
            current_record: ArcSwap::new(Arc::new(record)),
            tx_handle: tx,
            export_pipeline: Mutex::new(export_pipe),
            attribution,
            export_interval,
            last_export_epoch_ms: AtomicU64::new(epoch_ms_now()),
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
        self.finish_record_with_pipeline(&export_pipeline);
    }

    /// Shared export logic used by both `finish_record` and the passive export
    /// path. The caller must already hold the pipeline lock.
    fn finish_record_with_pipeline(&self, export_pipeline: &ExportPipeline<S>) {
        let new_record = Arc::new(HandshakeRecordInProgress::new(self.inner.tx_handle.clone()));

        let old_record = self.inner.current_record.swap(new_record);
        // On drop, the record will be "frozen" and written to the channel
        // This might not happen immediately because other threads might also hold
        // a reference to the metric record
        drop(old_record);

        // This will block the thread until the record is received.
        let handshake = export_pipeline.metric_receiver.recv().unwrap();
        let record = MetricRecord::new(handshake, self.inner.attribution.clone());
        export_pipeline.sink.export_record(&record);
        self.inner
            .last_export_epoch_ms
            .store(epoch_ms_now(), Ordering::Relaxed);
    }

    /// Check whether the export interval has elapsed and, if so, try to export.
    ///
    /// Uses `try_lock` so that the handshake thread is never blocked waiting
    /// for an export that is already in progress on another thread.
    fn try_periodic_export(&self) {
        let interval = match self.inner.export_interval {
            Some(d) => d,
            None => return,
        };

        let last = self.inner.last_export_epoch_ms.load(Ordering::Relaxed);
        let now = epoch_ms_now();
        if now.saturating_sub(last) < interval.as_millis() as u64 {
            return;
        }

        // try_lock: if another thread is already exporting, skip this attempt
        if let Ok(pipeline) = self.inner.export_pipeline.try_lock() {
            // Re-check after acquiring the lock — another thread may have
            // exported between our check and the lock acquisition.
            let last = self.inner.last_export_epoch_ms.load(Ordering::Relaxed);
            if epoch_ms_now().saturating_sub(last) >= interval.as_millis() as u64 {
                self.finish_record_with_pipeline(&pipeline);
            }
        }
    }
}

impl<S: TelemetrySink> EventSubscriber for AggregatedMetricsSubscriber<S> {
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
        // Drop the Arc before attempting export so that finish_record can
        // observe the final reference count drop.
        drop(current_record);

        self.try_periodic_export();
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

    /// Multiple finish_record() calls should each produce a separate record
    /// in the sink, and records should accumulate in order.
    #[test]
    fn multiple_finish_record_buffering() {
        let endpoint = TestEndpoint::new();

        // First batch: 2 handshakes
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();

        // Second batch: 1 handshake
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();

        // Third: empty record (no handshakes)
        endpoint.subscriber.finish_record();

        let records = endpoint.sink.records.lock().unwrap();
        assert_eq!(
            records.len(),
            3,
            "expected 3 records from 3 finish_record calls"
        );

        // Verify handshake counts
        assert_eq!(records[0].handshake.handshake_count, 2);
        assert_eq!(records[1].handshake.handshake_count, 1);
        assert_eq!(records[2].handshake.handshake_count, 0);
    }

    /// Passive export: when the interval has elapsed, the next handshake
    /// triggers an automatic export without an explicit finish_record call.
    #[test]
    fn passive_export_triggers_on_handshake() {
        use crate::{AggregatedMetricsSubscriber, Attribution, test_utils::VecSink};
        use s2n_tls::{
            security::DEFAULT_TLS13,
            testing::{build_config, config_builder},
        };
        use std::time::Duration;

        let sink = VecSink::new();
        let attribution = Attribution {
            service: "test_server".to_owned(),
            resource: "test_resource".to_owned(),
        };
        // Use a zero-duration interval so every handshake triggers an export
        let subscriber = AggregatedMetricsSubscriber::with_periodic_export(
            sink.clone(),
            attribution,
            Duration::ZERO,
        );
        let server_config = {
            let mut config = config_builder(&DEFAULT_TLS13).unwrap();
            config.set_event_subscriber(subscriber.clone()).unwrap();
            config.build().unwrap()
        };

        let client_config = build_config(&ARBITRARY_POLICY_1).unwrap();
        let mut pair = s2n_tls::testing::TestPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();

        // The handshake itself should have triggered a passive export
        let records = sink.records.lock().unwrap();
        assert_eq!(
            records.len(),
            1,
            "passive export should have produced a record"
        );
    }
}
