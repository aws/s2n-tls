// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{
    mpsc::{self, Receiver, Sender},
    LazyLock,
};

use s2n_tls::{
    security::{Policy, DEFAULT_TLS13},
    testing::{build_config, config_builder, TestPair},
};

use crate::{emf_emitter::EmfEmitter, record::MetricRecord, AggregatedMetricsSubscriber};

// arbitrary numbered policies that won't change. We use two different policies
// to get a variety of metrics.
pub(crate) static ARBITRARY_POLICY_1: LazyLock<Policy> =
    LazyLock::new(|| Policy::from_version("20240503").unwrap());
pub(crate) static ARBITRARY_POLICY_2: LazyLock<Policy> =
    LazyLock::new(|| Policy::from_version("20190214").unwrap());

pub struct TestEndpoint<T> {
    pub server_config: s2n_tls::config::Config,
    pub subscriber: AggregatedMetricsSubscriber<Sender<MetricRecord>>,
    pub exporter: T,
}

impl<T> TestEndpoint<T> {
    pub fn client_handshake(&self, client_policy: &Policy) -> TestPair {
        let client_config = build_config(client_policy).unwrap();
        let mut pair = TestPair::from_configs(&client_config, &self.server_config);
        pair.handshake().unwrap();
        pair
    }
}

impl TestEndpoint<Receiver<MetricRecord>> {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        let subscriber = AggregatedMetricsSubscriber::new(tx);

        let server_config = {
            let mut config = config_builder(&DEFAULT_TLS13).unwrap();
            config.set_event_subscriber(subscriber.clone()).unwrap();
            config.build().unwrap()
        };

        Self {
            server_config,
            subscriber,
            exporter: rx,
        }
    }
}

impl TestEndpoint<EmfEmitter> {
    pub fn new(resource: &str, policy: &Policy) -> Self {
        let (exporter, tx) = EmfEmitter::new("test_server".to_owned(), Some(resource.to_owned()));
        let subscriber = AggregatedMetricsSubscriber::new(tx);

        let server_config = {
            let mut config = config_builder(policy).unwrap();
            config.set_event_subscriber(subscriber.clone()).unwrap();
            config.build().unwrap()
        };

        Self {
            server_config,
            subscriber,
            exporter,
        }
    }
}
