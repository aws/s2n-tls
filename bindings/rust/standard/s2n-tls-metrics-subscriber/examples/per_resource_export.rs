// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Example: Per-Resource Aggregated Export
//!
//! Demonstrates how to use the s2n-tls-metrics-subscriber crate to create
//! multiple subscribers with different resource names, sharing a single
//! write destination via `Arc`. Shows both periodic and manual export.
//!
//! Note: This example demonstrates the construction and usage patterns of the
//! API. It does not perform actual TLS handshakes (which require s2n-tls server
//! setup). To see exported MetricRecords, we use an `mpsc::Sender<MetricRecord>`
//! as the exporter, which implements the `Exporter` trait.

use std::sync::{mpsc, Arc};
use std::time::Duration;

use s2n_tls_metrics_subscriber::{
    AggregatedMetricsSubscriber, EmfEmitter, MetricRecord, WriterSink,
};

fn main() {
    // ── Step 1: Create a shared sink ────────────────────────────────────
    //
    // `WriterSink` wraps any `std::io::Write` with a Mutex so it can be
    // shared across threads. Wrapping it in an `Arc` lets multiple
    // EmfEmitters write to the same destination.
    let shared_sink = Arc::new(WriterSink::new(Vec::<u8>::new()));

    // ── Step 2: Create an EmfEmitter with the shared sink ───────────────
    //
    // `EmfEmitter` formats `MetricRecord`s as CloudWatch EMF JSON and
    // writes them through the sink. The service name becomes a dimension
    // in CloudWatch metrics.
    let emitter_a = EmfEmitter::new("my-service".to_owned(), Arc::clone(&shared_sink));

    // ── Step 3: Create a subscriber with a resource name ────────────────
    //
    // `with_resource_name` tags every exported MetricRecord with the given
    // name. This lets you distinguish metrics from different resources
    // (e.g. different server endpoints) in the same service.
    let subscriber_a =
        AggregatedMetricsSubscriber::with_resource_name(emitter_a, "frontend-server");

    // ── Step 4: Create a second subscriber sharing the same sink ────────
    //
    // Because `EmfSink` is implemented for `Arc<T> where T: EmfSink`,
    // both emitters write to the same underlying `Vec<u8>`.
    let emitter_b = EmfEmitter::new("my-service".to_owned(), Arc::clone(&shared_sink));
    let subscriber_b =
        AggregatedMetricsSubscriber::with_resource_name(emitter_b, "backend-server");

    // ── Step 5: Start periodic export ───────────────────────────────────
    //
    // `start_periodic_export` spawns a background thread that calls
    // `finish_record()` at the given interval. The returned handle stops
    // the thread and performs a final export when dropped.
    let _export_handle = subscriber_a.start_periodic_export(Duration::from_secs(60));

    // ── Step 6: Manual export as an alternative ─────────────────────────
    //
    // You can also call `finish_record()` directly to export on demand.
    // This aggregates all events since the last export into a single
    // MetricRecord and passes it to the exporter.
    subscriber_b.finish_record();

    // ── Step 7: Reading the resource name from a MetricRecord ───────────
    //
    // To inspect MetricRecords programmatically, use an `mpsc::Sender` as
    // the exporter. It implements `Exporter` and sends each record through
    // the channel.
    let (tx, rx) = mpsc::channel::<MetricRecord>();
    let inspector =
        AggregatedMetricsSubscriber::with_resource_name(tx, "inspectable-server");

    // In a real application, TLS handshake events would populate the
    // record. Here we just export the (empty) record to show the API.
    inspector.finish_record();

    // Receive the exported record and read its resource name.
    let record = rx.recv().expect("should receive a MetricRecord");
    assert_eq!(record.resource_name(), Some("inspectable-server"));
    println!("Resource name: {:?}", record.resource_name());

    println!("Example complete.");
}
