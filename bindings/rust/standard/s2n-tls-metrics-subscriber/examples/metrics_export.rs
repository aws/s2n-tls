// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Demonstrates how to wire an `AggregatedMetricsSubscriber` into an s2n-tls
//! config, perform handshakes, and export the aggregated metrics as JSON.
//!
//! The subscriber is tagged with an `Attribution` so that the exported record
//! identifies which service and resource produced the metrics.
//!
//! The `TelemetrySink` receives a `MetricRecord` which implements
//! `serde::Serialize`, so the sink decides the serialization format.

use std::{
    io::{self, Write},
    time::Duration,
};

use s2n_tls::{
    security::DEFAULT_TLS13,
    testing::{TestPair, build_config, config_builder},
};

use s2n_tls_metrics_subscriber::{
    AggregatedMetricsSubscriber, Attribution, MetricRecord, TelemetrySink,
};

/// Example TelemetrySink that serializes each record as JSON and writes it
/// to stdout. Applications can implement TelemetrySink to route records to
/// any destination and serialize in any format (JSON, CBOR, etc.).
#[derive(Clone)]
struct StdoutJsonSink;

impl TelemetrySink for StdoutJsonSink {
    fn export_record(&self, record: &MetricRecord) {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        // MetricRecord implements serde::Serialize, so we can use serde_json
        if let Err(e) = serde_json::to_writer(&mut handle, record) {
            eprintln!("failed to serialize metric record: {e}");
            return;
        }
        let _ = handle.write_all(b"\n");
        let _ = handle.flush();
    }
}

fn main() {
    let attribution = Attribution {
        service: "my-service".to_owned(),
        resource: "test-resource".to_owned(),
    };

    // Passive periodic export: the subscriber will automatically export
    // the aggregated record during handshake processing once 60 seconds
    // have elapsed since the last export. No background thread needed.
    let subscriber = AggregatedMetricsSubscriber::with_periodic_export(
        StdoutJsonSink,
        attribution,
        Duration::from_secs(60),
    );

    // Wire the subscriber into a server config so handshake events flow into it.
    let server_config = {
        let mut builder = config_builder(&DEFAULT_TLS13).unwrap();
        builder.set_event_subscriber(subscriber.clone()).unwrap();
        builder.build().unwrap()
    };
    let client_config = build_config(&DEFAULT_TLS13).unwrap();

    // Perform a few handshakes so there is real data to export.
    for _ in 0..3 {
        let mut pair = TestPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();
    }

    // Final flush — export any remaining accumulated metrics.
    subscriber.finish_record();
}
