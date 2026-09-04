// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, LazyLock, Mutex};

use s2n_tls::{
    security::{DEFAULT_TLS13, Policy},
    testing::{TestPair, build_config, config_builder},
};

use crate::{
    AggregatedMetricsSubscriber, Attribution, MetricRecord, telemetry_sink::TelemetrySink,
};

pub(crate) static ARBITRARY_POLICY_1: LazyLock<Policy> =
    LazyLock::new(|| Policy::from_version("20240503").unwrap());

/// A policy whose most preferred group is `secp256r1`, so a client using it will
/// send a `secp256r1` key share.
pub(crate) static P256_PREFERRING_POLICY: LazyLock<Policy> =
    LazyLock::new(|| Policy::from_version("20240503").unwrap());

/// A policy with `secp384r1` as a strongly preferred group. A server using this
/// policy will send a HelloRetryRequest to any client that key shares a
/// different group, e.g. a [`P256_PREFERRING_POLICY`] client.
pub(crate) static STRONGLY_PREFERRED_GROUPS_POLICY: LazyLock<Policy> =
    LazyLock::new(|| Policy::from_version("20251117").unwrap());

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
    fn export_record(&self, record: MetricRecord) {
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
        Self::with_server_policy(&DEFAULT_TLS13)
    }

    pub fn with_server_policy(server_policy: &Policy) -> Self {
        let sink = VecSink::new();
        let attribution = Attribution {
            service: "test_server".to_owned(),
            resource: "test_resource".to_owned(),
            component: "test_component".to_owned(),
        };
        let subscriber = AggregatedMetricsSubscriber::new(sink.clone(), attribution);
        let server_config = {
            let mut config = config_builder(server_policy).unwrap();
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
