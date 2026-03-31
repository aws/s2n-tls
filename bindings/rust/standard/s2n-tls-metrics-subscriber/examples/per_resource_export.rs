// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Demonstrates how to wire an `AggregatedMetricsSubscriber` into an s2n-tls
//! config, perform handshakes, and export the aggregated metrics as JSON.
//!
//! The subscriber is tagged with an `Attribution` so that the exported record
//! identifies which service and resource produced the metrics.

use std::io::{self, Write};

use s2n_tls::{
    security::DEFAULT_TLS13,
    testing::{TestPair, build_config, config_builder},
};

use s2n_tls_metrics_subscriber::{
    AggregatedMetricsSubscriber, Attribution, SerializationFormat, Sink,
};

/// A simple Sink that writes each JSON record to stdout followed by a newline.
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
    let attribution = Attribution {
        platform: "my-service".into(),
        resource: "test-resource".into(),
    };
    let subscriber =
        AggregatedMetricsSubscriber::new(StdoutSink, SerializationFormat::Querylog, attribution);

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

    // Flush the aggregated record. This prints one JSON line to stdout
    // containing attribution metadata and handshake metrics from the
    // three handshakes above.
    subscriber.finish_record();
}
