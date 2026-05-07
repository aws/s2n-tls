// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, LazyLock, Mutex};

use s2n_tls::{
    security::{DEFAULT_TLS13, Policy},
    testing::{TestPair, build_config, config_builder},
};

use crate::{
    AggregatedMetricsSubscriber, MetricRecord, attribution::Attribution,
    telemetry_sink::TelemetrySink,
};

pub(crate) static ARBITRARY_POLICY_1: LazyLock<Policy> =
    LazyLock::new(|| Policy::from_version("20240503").unwrap());

/// A test helper that implements [`TelemetrySink`] by collecting records into a Vec.
#[derive(Debug, Clone)]
pub(crate) struct VecSink {
    pub(crate) records: Arc<Mutex<Vec<MetricRecord>>>,
}

impl VecSink {
    pub(crate) fn new() -> Self {
        Self {
            records: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl TelemetrySink for VecSink {
    fn export_record(&self, record: &MetricRecord) {
        self.records.lock().unwrap().push(record.clone());
    }
}

pub(crate) struct TestEndpoint<S: TelemetrySink> {
    pub server_config: s2n_tls::config::Config,
    pub subscriber: AggregatedMetricsSubscriber<S>,
    pub sink: S,
}

impl<S: TelemetrySink> TestEndpoint<S> {
    pub fn client_handshake(&self, client_policy: &Policy) -> TestPair {
        let client_config = build_config(client_policy).unwrap();
        let mut pair = TestPair::from_configs(&client_config, &self.server_config);
        pair.handshake().unwrap();
        pair
    }
}

impl TestEndpoint<VecSink> {
    pub fn new() -> Self {
        let sink = VecSink::new();
        let attribution = Attribution {
            service: "test_server".to_owned(),
            resource: "test_resource".to_owned(),
        };
        let subscriber = AggregatedMetricsSubscriber::new(sink.clone(), attribution);
        let server_config = {
            let mut config = config_builder(&DEFAULT_TLS13).unwrap();
            config.set_event_subscriber(subscriber.clone()).unwrap();
            config.build().unwrap()
        };
        Self {
            server_config,
            subscriber,
            sink,
        }
    }
}
