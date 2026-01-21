// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::mpsc::{self, Receiver, Sender};

use s2n_tls::{
    security::{Policy, DEFAULT_TLS13},
    testing::{build_config, config_builder, TestPair},
};

use crate::{record::MetricRecord, AggregatedMetricsSubscriber};

pub struct TestEndpoint {
    pub server_config: s2n_tls::config::Config,
    pub subscriber: AggregatedMetricsSubscriber<Sender<MetricRecord>>,
    pub rx: Receiver<MetricRecord>,
}

impl TestEndpoint {
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
            rx,
        }
    }

    pub fn client_handshake(&self) -> TestPair {
        let client_config = build_config(&DEFAULT_TLS13).unwrap();
        let mut pair = TestPair::from_configs(&client_config, &self.server_config);
        pair.handshake().unwrap();
        pair
    }
}
