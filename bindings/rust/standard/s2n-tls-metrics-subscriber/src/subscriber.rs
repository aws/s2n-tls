// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls_metrics_schema::record::FrozenHandshakeRecord;

use crate::{
    Attribution, MetricRecord, detector::SyntheticTrafficDetector,
    record::HandshakeRecordInProgress, telemetry_sink::TelemetrySink,
};
use arc_swap::ArcSwap;
use rand::Rng;
use s2n_tls::events::EventSubscriber;
use std::{
    sync::{
        Arc, Mutex, OnceLock,
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

impl<S: TelemetrySink> ExportPipeline<S> {
    fn export_record(&self, handshake: FrozenHandshakeRecord, attribution: &Attribution) -> bool {
        let record = MetricRecord::new(s2n_tls_metrics_schema::record::MetricRecord {
            attribution: attribution.clone().into_schema(),
            handshake,
        });
        if record.is_empty() {
            return false;
        }
        self.sink.export_record(record);
        true
    }
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
    /// Lifecycle counts and interval peaks, sampled together at export time.
    /// This lock is never held while aggregating events or exporting to the sink.
    concurrency: Mutex<Concurrency>,
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

    /// Optional plug-in for marking handshakes as synthetic traffic.
    /// Installed once via `with_synthetic_traffic_detector`; the hot path
    /// reads it lock-free.
    synthetic_detector: OnceLock<Box<dyn SyntheticTrafficDetector>>,
}

#[derive(Debug, Default)]
struct Concurrency {
    connections: ConcurrencyCount,
    handshakes: ConcurrencyCount,
}

#[derive(Debug, Default)]
struct ConcurrencyCount {
    current: u64,
    peak: u64,
}

impl ConcurrencyCount {
    fn increment(&mut self) {
        self.current += 1;
        self.peak = self.peak.max(self.current);
    }

    fn decrement(&mut self) {
        self.current -= 1;
    }

    fn sample(&mut self) -> (u64, u64) {
        let peak = self.peak;
        // Counts still live at this boundary contribute to the next interval too.
        self.peak = self.current;
        (self.current, peak)
    }
}

impl<S: TelemetrySink> MetricSubscriberInner<S> {
    fn sample_concurrency(&self, handshake: &mut FrozenHandshakeRecord) {
        // Updating a count and its peak must be atomic with respect to sampling.
        // Separate atomics allow a delayed peak update to carry a previous
        // interval's spike into the next interval after sampling resets it.
        let mut concurrency = self.concurrency.lock().unwrap();
        (
            handshake.connection_concurrency,
            handshake.p100_connection_concurrency,
        ) = concurrency.connections.sample();
        (
            handshake.handshake_concurrency,
            handshake.p100_handshake_concurrency,
        ) = concurrency.handshakes.sample();
    }
}

fn epoch_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Compute a timestamp between "now" and "now minus internal"
///
/// This is necessary to smooth out export behavior. If 600 subscribers were created
/// at the same time, with an export interval of 60s, we want 10 subscribers to
/// export each second, not 600 subscribers exporting at once.
fn jittered_initial_export_placeholder(interval: Option<Duration>) -> u64 {
    let now = epoch_ms_now();
    match interval {
        Some(interval) => {
            let interval_ms = interval.as_millis() as u64;
            // `gen_range` panics on an empty range, so guard the zero case.
            let offset = if interval_ms == 0 {
                0
            } else {
                rand::rng().random_range(0..=interval_ms)
            };
            now.saturating_sub(offset)
        }
        // No periodic export configured; the seed is only used as a baseline.
        None => now,
    }
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
            concurrency: Mutex::new(Concurrency::default()),
            tx_handle: tx,
            export_pipeline: Mutex::new(export_pipe),
            attribution,
            export_interval,
            last_export_epoch_ms: AtomicU64::new(jittered_initial_export_placeholder(
                export_interval,
            )),
            synthetic_detector: OnceLock::new(),
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Install a detector that flags certain handshakes as synthetic traffic
    /// (e.g. scanners, health-checks, load tests). When it returns `true`, the
    /// subscriber increments `synthetic_traffic_count` and skips the other
    /// handshake event metrics. Concurrency counts still include synthetic traffic,
    /// because lifecycle events occur before the detector runs.
    ///
    /// Must be called before any handshake traffic begins. Subsequent calls
    /// are silently ignored.
    pub fn with_synthetic_traffic_detector(
        self,
        detector: Box<dyn SyntheticTrafficDetector>,
    ) -> Self {
        let _ = self.inner.synthetic_detector.set(detector);
        self
    }

    /// Finish aggregation of the record and export it.
    ///
    /// Records with no handshakes are exported when current or peak concurrency
    /// is nonzero. Empty records are skipped.
    ///
    /// Concurrency is sampled after the previous record's updates finish. Its
    /// sampling boundary can be later than the swap that ends event aggregation.
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
        let mut handshake = export_pipeline.metric_receiver.recv().unwrap();
        self.inner.sample_concurrency(&mut handshake);
        if !export_pipeline.export_record(handshake, &self.inner.attribution) {
            return;
        }
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

/// Flush any remaining aggregated events when the subscriber is fully dropped.
impl<S: TelemetrySink> Drop for MetricSubscriberInner<S> {
    fn drop(&mut self) {
        // Because the inner state is only dropped once the last
        // `AggregatedMetricsSubscriber` handle is gone, there are no concurrent
        // handshake threads still updating the record, so the swapped-out Arc
        // is guaranteed to be the last reference and its `Drop` runs inline.
        let placeholder = Arc::new(HandshakeRecordInProgress::new(self.tx_handle.clone()));
        let final_record = self.current_record.swap(placeholder);
        drop(final_record);

        // Export the frozen record. `drop` can't propagate errors, so if the
        // lock is poisoned or the record can't be received we silently bail
        // out rather than panic while tearing the subscriber down.
        let Ok(export_pipeline) = self.export_pipeline.lock() else {
            return;
        };
        let Ok(mut handshake) = export_pipeline.metric_receiver.try_recv() else {
            return;
        };
        self.sample_concurrency(&mut handshake);
        export_pipeline.export_record(handshake, &self.attribution);
    }
}

impl<S: TelemetrySink> EventSubscriber for AggregatedMetricsSubscriber<S> {
    fn on_handshake_started(&self, _connection: &s2n_tls::connection::Connection) {
        self.inner
            .concurrency
            .lock()
            .unwrap()
            .handshakes
            .increment();
    }

    fn on_handshake_finished(&self, _connection: &s2n_tls::connection::Connection) {
        self.inner
            .concurrency
            .lock()
            .unwrap()
            .handshakes
            .decrement();
    }

    fn on_connection_added(&self, _connection: &s2n_tls::connection::Connection) {
        self.inner
            .concurrency
            .lock()
            .unwrap()
            .connections
            .increment();
    }

    fn on_connection_removed(&self, _connection: &s2n_tls::connection::Connection) {
        self.inner
            .concurrency
            .lock()
            .unwrap()
            .connections
            .decrement();
    }

    fn on_handshake_event(
        &self,
        connection: &s2n_tls::connection::Connection,
        event: &s2n_tls::events::HandshakeEvent,
    ) {
        let current_record = self.inner.current_record.load_full();
        let detector = self
            .inner
            .synthetic_detector
            .get()
            .map(|boxed| boxed.as_ref());
        current_record.update(connection, event, detector);
        // Drop the Arc before attempting export so that finish_record can
        // observe the final reference count drop.
        drop(current_record);

        self.try_periodic_export();
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{ARBITRARY_POLICY_1, TestEndpoint, VecSink};

    fn concurrency(endpoint: &TestEndpoint<VecSink>) -> u64 {
        endpoint
            .subscriber
            .inner
            .concurrency
            .lock()
            .unwrap()
            .connections
            .current
    }

    fn handshake_concurrency(endpoint: &TestEndpoint<VecSink>) -> u64 {
        endpoint
            .subscriber
            .inner
            .concurrency
            .lock()
            .unwrap()
            .handshakes
            .current
    }

    #[test]
    fn handshake_peak_resets_each_interval_and_completion_clears_current() {
        use s2n_tls::testing::{TestPair, build_config};

        let endpoint = TestEndpoint::new();
        let client_config = build_config(&ARBITRARY_POLICY_1).unwrap();
        let mut pairs: Vec<_> = (0..100)
            .map(|_| TestPair::from_configs(&client_config, &endpoint.server_config))
            .collect();
        assert_eq!(handshake_concurrency(&endpoint), 0);
        for pair in &mut pairs {
            assert!(pair.server.poll_negotiate().is_pending());
            assert!(pair.server.poll_negotiate().is_pending());
        }
        assert_eq!(handshake_concurrency(&endpoint), 100);
        let mut remaining = pairs.pop().unwrap();
        drop(pairs);
        assert_eq!(handshake_concurrency(&endpoint), 1);
        endpoint.subscriber.finish_record();
        endpoint.subscriber.finish_record();

        remaining.handshake().unwrap();
        assert_eq!(handshake_concurrency(&endpoint), 0);
        assert_eq!(concurrency(&endpoint), 1);
        assert!(remaining.server.poll_negotiate().is_ready());
        assert_eq!(handshake_concurrency(&endpoint), 0);
        endpoint.subscriber.finish_record();
        endpoint.subscriber.finish_record();

        let records = endpoint.sink.records.lock().unwrap();
        let samples: Vec<_> = records
            .iter()
            .map(|record| {
                let handshake = &record.as_schema().handshake;
                (
                    handshake.handshake_concurrency,
                    handshake.p100_handshake_concurrency,
                )
            })
            .collect();
        assert_eq!(samples, [(1, 100), (1, 1), (0, 1), (0, 0)]);
    }

    #[test]
    fn active_handshake_transfers_between_tuple_subscribers_and_cancels_on_drop() {
        use s2n_tls::{
            security::DEFAULT_TLS13,
            testing::{TestPair, build_config, config_builder},
        };

        let previous = TestEndpoint::new();
        let next = TestEndpoint::new();
        let mut builder = config_builder(&DEFAULT_TLS13).unwrap();
        builder
            .set_event_subscriber((previous.subscriber.clone(), next.subscriber.clone()))
            .unwrap();
        let shared_config = builder.build().unwrap();
        let client_config = build_config(&ARBITRARY_POLICY_1).unwrap();
        let mut pair = TestPair::from_configs(&client_config, &previous.server_config);
        assert!(pair.server.poll_negotiate().is_pending());
        assert_eq!(handshake_concurrency(&previous), 1);
        pair.server.set_config(shared_config.clone()).unwrap();
        pair.server.set_config(shared_config).unwrap();
        assert_eq!(handshake_concurrency(&previous), 1);
        assert_eq!(handshake_concurrency(&next), 1);
        pair.server.set_config(next.server_config.clone()).unwrap();
        assert_eq!(handshake_concurrency(&previous), 0);
        assert_eq!(handshake_concurrency(&next), 1);
        pair.server
            .set_config(build_config(&ARBITRARY_POLICY_1).unwrap())
            .unwrap();
        assert_eq!(handshake_concurrency(&next), 0);
        pair.server.set_config(next.server_config.clone()).unwrap();
        assert_eq!(handshake_concurrency(&next), 1);
        drop(pair);
        assert_eq!(handshake_concurrency(&previous), 0);
        assert_eq!(handshake_concurrency(&next), 0);
    }

    #[test]
    fn failed_handshake_clears_concurrency_before_export() {
        use s2n_tls::{
            security::DEFAULT_TLS13,
            testing::{TestPair, build_config},
        };

        let incompatible = s2n_tls::security::Policy::from_version("20141001").unwrap();
        let endpoint = TestEndpoint::with_server_policy(&incompatible);
        let client_config = build_config(&DEFAULT_TLS13).unwrap();
        let mut pair = TestPair::from_configs(&client_config, &endpoint.server_config);
        pair.server
            .set_waker(Some(std::task::Waker::noop()))
            .unwrap();
        assert!(pair.client.poll_negotiate().is_pending());
        assert!(matches!(
            pair.server.poll_negotiate(),
            std::task::Poll::Ready(Err(_))
        ));
        assert_eq!(handshake_concurrency(&endpoint), 0);
        endpoint.subscriber.finish_record();

        let records = endpoint.sink.records.lock().unwrap();
        let handshake = &records[0].as_schema().handshake;
        assert_eq!(handshake.handshake_failure_count, 1);
        assert_eq!(handshake.handshake_concurrency, 0);
        assert_eq!(handshake.p100_handshake_concurrency, 1);
    }

    #[test]
    fn initializer_failure_clears_concurrency_without_a_c_result_event() {
        use s2n_tls::{
            callbacks::ConnectionFuture, config::ConnectionInitializer, connection::Connection,
            error::Error, security::DEFAULT_TLS13, testing::config_builder,
        };
        use std::pin::Pin;

        struct FailInitializer;
        impl ConnectionInitializer for FailInitializer {
            fn initialize_connection(
                &self,
                _connection: &mut Connection,
            ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error> {
                Err(Error::application("initializer failed".into()))
            }
        }

        let endpoint = TestEndpoint::new();
        let mut builder = config_builder(&DEFAULT_TLS13).unwrap();
        builder
            .set_event_subscriber(endpoint.subscriber.clone())
            .unwrap();
        builder.set_connection_initializer(FailInitializer).unwrap();
        let mut connection = Connection::new_server();
        connection.set_config(builder.build().unwrap()).unwrap();
        connection
            .set_waker(Some(std::task::Waker::noop()))
            .unwrap();
        assert!(matches!(
            connection.poll_negotiate(),
            std::task::Poll::Ready(Err(_))
        ));
        assert_eq!(handshake_concurrency(&endpoint), 0);
        drop(connection);
        endpoint.subscriber.finish_record();
        let records = endpoint.sink.records.lock().unwrap();
        let handshake = &records[0].as_schema().handshake;
        assert_eq!(handshake.handshake_concurrency, 0);
        assert_eq!(handshake.p100_handshake_concurrency, 1);
        assert_eq!(handshake.handshake_failure_count, 0);
    }

    #[test]
    fn concurrency_without_handshakes_reports_peaks_and_skips_idle_records() {
        use s2n_tls::connection::Connection;

        let endpoint = TestEndpoint::new();
        endpoint.subscriber.finish_record();
        endpoint.subscriber.finish_record();
        assert!(endpoint.sink.records.lock().unwrap().is_empty());

        // Even connections dropped before export contribute to the peak.
        let mut unsampled = Connection::new_server();
        unsampled
            .set_config(endpoint.server_config.clone())
            .unwrap();
        drop(unsampled);
        endpoint.subscriber.finish_record();
        assert_eq!(
            endpoint.sink.records.lock().unwrap()[0]
                .as_schema()
                .handshake
                .p100_connection_concurrency,
            1
        );

        for _ in 0..2 {
            let mut pending = Connection::new_server();
            pending.set_config(endpoint.server_config.clone()).unwrap();
            endpoint.subscriber.finish_record();
            endpoint.subscriber.finish_record();
            drop(pending);
            endpoint.subscriber.finish_record();
            endpoint.subscriber.finish_record();
            endpoint.subscriber.finish_record();
        }

        let records = endpoint.sink.records.lock().unwrap();
        let counts: Vec<_> = records
            .iter()
            .map(|record| record.as_schema().handshake.connection_concurrency)
            .collect();
        assert_eq!(counts, [0, 1, 1, 0, 1, 1, 0]);
        assert!(records.iter().all(|record| {
            let handshake = &record.as_schema().handshake;
            handshake.p100_connection_concurrency == 1
                && handshake.handshake_success_count == 0
                && handshake.handshake_failure_count == 0
        }));
    }

    #[test]
    fn drop_flushes_peak_without_repeating_an_exported_peak() {
        use s2n_tls::connection::Connection;

        for explicitly_export_peak in [false, true] {
            let endpoint = TestEndpoint::new();
            let mut pending = Connection::new_server();
            pending.set_config(endpoint.server_config.clone()).unwrap();
            endpoint.subscriber.finish_record();
            drop(pending);
            if explicitly_export_peak {
                endpoint.subscriber.finish_record();
            }

            let TestEndpoint {
                subscriber,
                sink,
                server_config,
            } = endpoint;
            drop(subscriber);
            drop(server_config);

            let records = sink.records.lock().unwrap();
            let counts: Vec<_> = records
                .iter()
                .map(|record| record.as_schema().handshake.connection_concurrency)
                .collect();
            assert_eq!(counts, [1, 0]);
            assert!(
                records.iter().all(|record| {
                    record.as_schema().handshake.p100_connection_concurrency == 1
                })
            );
        }
    }

    #[test]
    fn concurrency_is_sampled_at_export_and_persists_across_records() {
        use s2n_tls::connection::Connection;

        let endpoint = TestEndpoint::new();
        let pair = endpoint.client_handshake(&ARBITRARY_POLICY_1);
        // Connections whose handshakes have not started also count.
        let mut pending = Connection::new_server();
        pending.set_config(endpoint.server_config.clone()).unwrap();
        endpoint.subscriber.finish_record();

        // Exporting resets handshake counters, but not live concurrency.
        endpoint.subscriber.finish_record();
        // The third interval starts with two live connections, so its peak is
        // two even though both close before the next export.
        drop(pending);
        drop(pair);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();
        endpoint.subscriber.finish_record();

        let records = endpoint.sink.records.lock().unwrap();
        assert_eq!(records.len(), 3);
        let counts: Vec<_> = records
            .iter()
            .map(|record| record.as_schema().handshake.connection_concurrency)
            .collect();
        assert_eq!(counts, [2, 2, 0]);
        let peaks: Vec<_> = records
            .iter()
            .map(|record| record.as_schema().handshake.p100_connection_concurrency)
            .collect();
        assert_eq!(peaks, [2, 2, 2]);
    }

    #[test]
    fn peak_concurrency_spike_does_not_carry_into_the_next_interval() {
        use s2n_tls::connection::Connection;

        let endpoint = TestEndpoint::new();
        let mut first = Connection::new_server();
        first.set_config(endpoint.server_config.clone()).unwrap();
        let spike: Vec<_> = (0..99)
            .map(|_| {
                let mut connection = Connection::new_server();
                connection
                    .set_config(endpoint.server_config.clone())
                    .unwrap();
                connection
            })
            .collect();
        assert_eq!(concurrency(&endpoint), 100);
        // The spike ends in this interval, leaving one connection alive.
        drop(spike);
        endpoint.subscriber.finish_record();
        endpoint.subscriber.finish_record();
        drop(first);
        endpoint.subscriber.finish_record();
        endpoint.subscriber.finish_record();

        let records = endpoint.sink.records.lock().unwrap();
        let samples: Vec<_> = records
            .iter()
            .map(|record| {
                let handshake = &record.as_schema().handshake;
                (
                    handshake.connection_concurrency,
                    handshake.p100_connection_concurrency,
                )
            })
            .collect();
        assert_eq!(samples, [(1, 100), (1, 1), (0, 1)]);
    }

    #[test]
    fn concurrency_moves_between_subscribers() {
        use s2n_tls::testing::build_config;

        let previous = TestEndpoint::new();
        let next = TestEndpoint::new();
        let mut pair = previous.client_handshake(&ARBITRARY_POLICY_1);
        pair.server.set_config(next.server_config.clone()).unwrap();
        previous.subscriber.finish_record();
        assert_eq!(
            previous.sink.records.lock().unwrap()[0]
                .as_schema()
                .handshake
                .connection_concurrency,
            0
        );

        // Generate a report in the new subscriber while the transferred
        // connection remains alive.
        next.client_handshake(&ARBITRARY_POLICY_1);
        next.subscriber.finish_record();
        assert_eq!(
            next.sink.records.lock().unwrap()[0]
                .as_schema()
                .handshake
                .connection_concurrency,
            1
        );

        // Setting the same config twice must not double-count the connection.
        pair.server.set_config(next.server_config.clone()).unwrap();
        assert_eq!(concurrency(&next), 1);

        // Moving to a config without a subscriber removes the old subscription.
        let without_subscriber = build_config(&ARBITRARY_POLICY_1).unwrap();
        pair.server.set_config(without_subscriber).unwrap();
        assert_eq!(concurrency(&next), 0);
        pair.server
            .set_config(previous.server_config.clone())
            .unwrap();
        assert_eq!(concurrency(&previous), 1);
        drop(pair);
        assert_eq!(concurrency(&previous), 0);
        assert_eq!(concurrency(&next), 0);
    }

    #[test]
    fn client_hello_config_change_transfers_concurrency() {
        use s2n_tls::{
            callbacks::{ClientHelloCallback, ConnectionFuture},
            config::Config,
            connection::Connection,
            error::Error,
            security::DEFAULT_TLS13,
            testing::{TestPair, build_config, config_builder},
        };
        use std::pin::Pin;

        struct SwitchConfig(Config);
        impl ClientHelloCallback for SwitchConfig {
            fn on_client_hello(
                &self,
                connection: &mut Connection,
            ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error> {
                connection.set_config(self.0.clone())?;
                Ok(None)
            }
        }

        let previous = TestEndpoint::new();
        let next = TestEndpoint::new();
        let mut builder = config_builder(&DEFAULT_TLS13).unwrap();
        builder
            .set_event_subscriber(previous.subscriber.clone())
            .unwrap();
        builder
            .set_client_hello_callback(SwitchConfig(next.server_config.clone()))
            .unwrap();
        let initial_config = builder.build().unwrap();
        let client_config = build_config(&ARBITRARY_POLICY_1).unwrap();
        let mut pair = TestPair::from_configs(&client_config, &initial_config);
        pair.server
            .set_waker(Some(std::task::Waker::noop()))
            .unwrap();
        assert_eq!(concurrency(&previous), 1);
        assert_eq!(concurrency(&next), 0);

        pair.handshake().unwrap();
        assert_eq!(concurrency(&previous), 0);
        assert_eq!(concurrency(&next), 1);
        assert_eq!(handshake_concurrency(&previous), 0);
        assert_eq!(handshake_concurrency(&next), 0);
        previous.subscriber.finish_record();
        assert_eq!(
            previous.sink.records.lock().unwrap()[0]
                .as_schema()
                .handshake
                .p100_handshake_concurrency,
            1
        );
        next.subscriber.finish_record();
        assert_eq!(
            next.sink.records.lock().unwrap()[0]
                .as_schema()
                .handshake
                .connection_concurrency,
            1
        );
        assert_eq!(
            next.sink.records.lock().unwrap()[0]
                .as_schema()
                .handshake
                .p100_handshake_concurrency,
            1
        );
        drop(pair);
        assert_eq!(concurrency(&next), 0);
    }

    #[test]
    fn concurrency_is_shared_between_configs_and_tuple_subscribers() {
        use s2n_tls::{connection::Connection, security::DEFAULT_TLS13, testing::config_builder};

        let first = TestEndpoint::new();
        let second = TestEndpoint::new();
        let mut builder = config_builder(&DEFAULT_TLS13).unwrap();
        builder
            .set_event_subscriber((first.subscriber.clone(), second.subscriber.clone()))
            .unwrap();
        let shared_config = builder.build().unwrap();

        let mut connection = Connection::new_server();
        connection.set_config(first.server_config.clone()).unwrap();
        connection.set_config(shared_config.clone()).unwrap();
        assert_eq!(concurrency(&first), 1);
        assert_eq!(concurrency(&second), 1);

        let mut other = Connection::new_client();
        other.set_config(shared_config).unwrap();
        assert_eq!(concurrency(&first), 2);
        assert_eq!(concurrency(&second), 2);
        drop(connection);
        drop(other);
        assert_eq!(concurrency(&first), 0);
        assert_eq!(concurrency(&second), 0);
    }

    #[test]
    fn failed_config_change_preserves_concurrency() {
        use s2n_tls::{connection::Connection, security::DEFAULT_TLS13, testing::CertKeyPair};

        let previous = TestEndpoint::new();
        let next = TestEndpoint::new();
        let mut connection = Connection::new_client();
        connection
            .set_config(previous.server_config.clone())
            .unwrap();

        // Client connections reject configs with more than one certificate.
        let mut builder = s2n_tls::config::Builder::new();
        builder.set_security_policy(&DEFAULT_TLS13).unwrap();
        builder
            .load_chain(CertKeyPair::default().into_certificate_chain())
            .unwrap();
        let extra_cert = CertKeyPair::from_path("ecdsa_p384_pkcs1_", "cert", "key", "cert");
        builder
            .load_chain(extra_cert.into_certificate_chain())
            .unwrap();
        builder
            .set_event_subscriber(next.subscriber.clone())
            .unwrap();
        let error = connection.set_config(builder.build().unwrap()).unwrap_err();
        assert_eq!(error.name(), "S2N_ERR_TOO_MANY_CERTIFICATES");
        assert_eq!(concurrency(&previous), 1);
        assert_eq!(concurrency(&next), 0);
        drop(connection);
        assert_eq!(concurrency(&previous), 0);
    }

    #[test]
    fn concurrency_updates_from_multiple_threads() {
        use s2n_tls::connection::Connection;

        let endpoint = TestEndpoint::new();
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        let mut connection = Connection::new_server();
                        connection
                            .set_config(endpoint.server_config.clone())
                            .unwrap();
                        connection
                    })
                })
                .collect();
            let connections: Vec<_> = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect();
            assert_eq!(concurrency(&endpoint), 16);
            for connection in connections {
                scope.spawn(move || drop(connection));
            }
        });
        assert_eq!(concurrency(&endpoint), 0);
        endpoint.subscriber.finish_record();
        assert_eq!(
            endpoint.sink.records.lock().unwrap()[0]
                .as_schema()
                .handshake
                .p100_connection_concurrency,
            16
        );
    }

    #[test]
    #[allow(deprecated)]
    fn wiping_pending_handshake_balances_counts_and_allows_a_new_handshake() {
        use s2n_tls::testing::{TestPair, build_config};

        let endpoint = TestEndpoint::new();
        let client_config = build_config(&ARBITRARY_POLICY_1).unwrap();
        let mut pair = TestPair::from_configs(&client_config, &endpoint.server_config);
        assert!(pair.server.poll_negotiate().is_pending());
        assert_eq!(handshake_concurrency(&endpoint), 1);

        pair.server.wipe().unwrap();
        assert_eq!(concurrency(&endpoint), 1);
        assert_eq!(handshake_concurrency(&endpoint), 0);

        // Reattach I/O to the replacement connection.
        let mut pair = TestPair::from_connections(pair.client, pair.server);
        assert!(pair.server.poll_negotiate().is_pending());
        assert_eq!(handshake_concurrency(&endpoint), 1);
        pair.handshake().unwrap();
        assert_eq!(handshake_concurrency(&endpoint), 0);
        drop(pair);
        assert_eq!(concurrency(&endpoint), 0);
    }

    /// assert that we see a good distribution of export times
    #[test]
    fn jittered_initial_deadline_desynchronizes_subscribers() {
        use super::jittered_initial_export_placeholder;
        use std::{collections::HashSet, time::Duration};

        let interval = Some(Duration::from_secs(3600));
        let seeds: HashSet<u64> = (0..100)
            .map(|_| jittered_initial_export_placeholder(interval))
            .collect();
        // we should see lots of unique export times
        assert!(seeds.len() > 50,);
    }

    /// A zero interval must not panic (the jitter range would otherwise be
    /// empty) and should seed with the current time.
    #[test]
    fn jittered_seed_handles_zero_interval() {
        use super::{epoch_ms_now, jittered_initial_export_placeholder};
        use std::time::Duration;

        let before = epoch_ms_now();
        let seed = jittered_initial_export_placeholder(Some(Duration::ZERO));
        let after = epoch_ms_now();
        assert!(seed >= before && seed <= after);
    }

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

        // Third: no handshakes
        endpoint.subscriber.finish_record();

        let records = endpoint.sink.records.lock().unwrap();
        assert_eq!(
            records.len(),
            2,
            "expected 2 records; the empty finish_record call should be skipped"
        );

        // Verify handshake counts
        assert_eq!(records[0].as_schema().handshake.handshake_success_count, 2);
        assert_eq!(records[1].as_schema().handshake.handshake_success_count, 1);
    }

    /// Dropping the subscriber should flush any events aggregated since the
    /// last export, so no records are lost when the subscriber goes away.
    #[test]
    fn drop_flushes_pending_record() {
        use crate::{AggregatedMetricsSubscriber, Attribution, test_utils::VecSink};
        use s2n_tls::{
            security::DEFAULT_TLS13,
            testing::{TestPair, build_config, config_builder},
        };

        let sink = VecSink::new();
        let attribution = Attribution {
            service: "test".to_owned(),
            resource: "test".to_owned(),
            component: "test".to_owned(),
        };
        let subscriber = AggregatedMetricsSubscriber::new(sink.clone(), attribution);
        let server_config = {
            let mut cfg = config_builder(&DEFAULT_TLS13).unwrap();
            cfg.set_event_subscriber(subscriber.clone()).unwrap();
            cfg.build().unwrap()
        };
        let client_config = build_config(&ARBITRARY_POLICY_1).unwrap();

        // Two handshakes, but no explicit finish_record() call.
        for _ in 0..2 {
            TestPair::from_configs(&client_config, &server_config)
                .handshake()
                .unwrap();
        }

        // No record should have been exported yet.
        assert_eq!(sink.records.lock().unwrap().len(), 0);

        // Drop every handle to the subscriber. The last drop must flush.
        drop(subscriber);
        drop(server_config);

        let records = sink.records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].as_schema().handshake.handshake_success_count, 2);
        assert_eq!(records[0].as_schema().handshake.connection_concurrency, 0);
    }

    /// Dropping intermediate clones must NOT flush; only the final drop should.
    #[test]
    fn drop_of_clone_does_not_flush() {
        let endpoint = TestEndpoint::new();
        endpoint.client_handshake(&ARBITRARY_POLICY_1);

        // Dropping a clone while other handles remain should not export.
        let clone = endpoint.subscriber.clone();
        drop(clone);

        assert_eq!(endpoint.sink.records.lock().unwrap().len(), 0,);
    }

    /// Dropping a subscriber that aggregated no handshakes must not export an
    /// empty record.
    #[test]
    fn drop_with_no_handshakes_does_not_flush() {
        let endpoint = TestEndpoint::new();
        // No handshakes performed.
        let TestEndpoint {
            subscriber,
            sink,
            server_config,
        } = endpoint;
        drop(subscriber);
        drop(server_config);

        assert_eq!(sink.records.lock().unwrap().len(), 0,);
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
            component: "test_component".to_owned(),
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
        assert_eq!(records[0].as_schema().handshake.connection_concurrency, 1);
        assert_eq!(records[0].as_schema().handshake.handshake_concurrency, 0);
        assert_eq!(
            records[0].as_schema().handshake.p100_handshake_concurrency,
            1
        );
    }

    /// Synthetic traffic contributes to concurrency and synthetic_traffic_count,
    /// but is excluded from the other handshake event metrics.
    #[test]
    fn synthetic_traffic_detector_increments_count() {
        use crate::{
            AggregatedMetricsSubscriber, Attribution, SyntheticTrafficDetector, test_utils::VecSink,
        };
        use s2n_tls::{
            client_hello::ClientHello,
            security::DEFAULT_TLS13,
            testing::{TestPair, build_config, config_builder},
        };
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        #[derive(Debug)]
        struct ToggleDetector(Arc<AtomicBool>);
        impl SyntheticTrafficDetector for ToggleDetector {
            fn is_synthetic(&self, _ch: &ClientHello) -> bool {
                self.0.load(Ordering::Relaxed)
            }
        }

        let toggle = Arc::new(AtomicBool::new(false));
        let sink = VecSink::new();
        let attribution = Attribution {
            service: "test_server".to_owned(),
            resource: "test_resource".to_owned(),
            component: "test_component".to_owned(),
        };
        let subscriber = AggregatedMetricsSubscriber::new(sink.clone(), attribution)
            .with_synthetic_traffic_detector(Box::new(ToggleDetector(toggle.clone())));
        let server_config = {
            let mut cfg = config_builder(&DEFAULT_TLS13).unwrap();
            cfg.set_event_subscriber(subscriber.clone()).unwrap();
            cfg.build().unwrap()
        };
        let client_config = build_config(&ARBITRARY_POLICY_1).unwrap();

        // 2 "real" handshakes, then 3 "synthetic" ones.
        for _ in 0..2 {
            TestPair::from_configs(&client_config, &server_config)
                .handshake()
                .unwrap();
        }
        toggle.store(true, Ordering::Relaxed);
        let synthetic_pairs: Vec<_> = (0..3)
            .map(|_| {
                let mut pair = TestPair::from_configs(&client_config, &server_config);
                pair.handshake().unwrap();
                pair
            })
            .collect();

        subscriber.finish_record();
        let records = sink.records.lock().unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0].as_schema().handshake;

        assert_eq!(record.handshake_success_count, 2);
        assert_eq!(record.synthetic_traffic_count, 3);
        assert_eq!(record.negotiated_protocols.total(), 2);
        assert_eq!(record.negotiated_ciphers.total(), 2);
        assert_eq!(record.connection_concurrency, 3);
        assert_eq!(record.p100_connection_concurrency, 3);
        assert_eq!(record.handshake_concurrency, 0);
        assert_eq!(record.p100_handshake_concurrency, 1);
        drop(records);
        drop(synthetic_pairs);
    }

    /// With no detector installed, `synthetic_traffic_count` stays at zero
    /// regardless of handshake volume.
    #[test]
    fn synthetic_traffic_count_zero_when_no_detector() {
        let endpoint = TestEndpoint::new();
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.client_handshake(&ARBITRARY_POLICY_1);
        endpoint.subscriber.finish_record();

        let records = endpoint.sink.records.lock().unwrap();
        assert_eq!(records[0].as_schema().handshake.handshake_success_count, 2);
        assert_eq!(records[0].as_schema().handshake.synthetic_traffic_count, 0);
    }
}
