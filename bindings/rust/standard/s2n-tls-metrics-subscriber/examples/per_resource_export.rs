// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shows how to tag metrics by resource name and export them as EMF JSON.
//!
//! Two subscribers share a single write destination (via Arc) but use different
//! resource names, so their metrics are distinguishable in the output.

use std::{sync::Arc, time::Duration};

use s2n_tls::{
    security::DEFAULT_TLS13,
    testing::{TestPair, build_config, config_builder},
};

use s2n_tls_metrics_subscriber::{AggregatedMetricsSubscriber, EmfEmitter, StdoutSink, WriterSink};

fn main() {
    // Both emitters write to the same buffer through a shared sink.
    let shared_sink = Arc::new(WriterSink::new(Vec::<u8>::new()));

    // Set up two subscribers with different resource names.
    let emitter_a = EmfEmitter::new("my-service".to_owned(), Arc::clone(&shared_sink));
    let subscriber_a = AggregatedMetricsSubscriber::with_resource_name(emitter_a, "resource-a");

    let emitter_b = EmfEmitter::new("my-service".to_owned(), Arc::clone(&shared_sink));
    let subscriber_b = AggregatedMetricsSubscriber::with_resource_name(emitter_b, "resource-b");

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
    subscriber_a.finish_record();

    // subscriber_b is only used to demonstrate periodic export setup here.
    // Since it is not attached to a config, it will not receive handshake
    // events in this example.
    let _handle = subscriber_b.start_periodic_export(Duration::from_secs(60));

    // You can also configure an emitter to write EMF records to stdout,
    // for example in container environments where EMF is collected from logs.
    // This emitter is not wired into a subscriber in this example.
    let _stdout_emitter = EmfEmitter::new("my-service".to_owned(), StdoutSink);

    println!("done");
}
