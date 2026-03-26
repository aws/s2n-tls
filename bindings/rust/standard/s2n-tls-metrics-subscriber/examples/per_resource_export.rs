// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shows how to tag metrics by resource name and export them using the `Sink` trait.
//!
//! Two subscribers use different `Attribution` values and serialization formats,
//! so their metrics are distinguishable in the output.

use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use s2n_tls::{
    security::DEFAULT_TLS13,
    testing::{TestPair, build_config, config_builder},
};

use s2n_tls_metrics_subscriber::{
    AggregatedMetricsSubscriber, Attribution, SerializationFormat, Sink,
};

/// A simple Sink that writes each record to stdout followed by a newline.
struct StdoutSink;

impl Sink for StdoutSink {
    fn write_record(&self, record: &[u8]) -> io::Result<()> {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        handle.write_all(record)?;
        handle.write_all(b"\n")?;
        handle.flush()
    }
}

fn main() {
    // Subscriber A: Querylog format, resource "api-gateway"
    let attribution_a = Attribution {
        platform: "my-service".into(),
        resource: "api-gateway".into(),
    };
    let subscriber_a = AggregatedMetricsSubscriber::new(
        StdoutSink,
        SerializationFormat::Querylog,
        attribution_a,
    );

    // Subscriber B: CBOR format, resource "internal-proxy"
    let attribution_b = Attribution {
        platform: "my-service".into(),
        resource: "internal-proxy".into(),
    };
    let subscriber_b = AggregatedMetricsSubscriber::new(
        Arc::new(StdoutSink),
        SerializationFormat::Cbor,
        attribution_b,
    );

    // Wire subscriber_a into a server config so handshake events flow into it.
    let server_config = {
        let mut builder = config_builder(&DEFAULT_TLS13).unwrap();
        builder.set_event_subscriber(subscriber_a.clone()).unwrap();
        builder.build().unwrap()
    };
    let client_config = build_config(&DEFAULT_TLS13).unwrap();

    // Do a few handshakes so there's real data to export.
    for _ in 0..3 {
        let mut pair = TestPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap();
    }

    // Manual export: flushes the aggregated record immediately.
    // Because subscriber_a uses Querylog format, this prints JSON to stdout.
    subscriber_a.finish_record();

    // Periodic export demo: subscriber_b will flush every 60 seconds.
    // Since it uses CBOR format, the output will be binary.
    // The handle must be kept alive for periodic export to continue.
    let _handle = subscriber_b.start_periodic_export(Duration::from_secs(60));

    println!("done");
}
