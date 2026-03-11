// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{
    Arc, LazyLock, Mutex,
    mpsc::{self, Receiver, Sender},
};

use s2n_tls::{
    security::{DEFAULT_TLS13, Policy},
    testing::{TestPair, build_config, config_builder},
};

use crate::{
    AggregatedMetricsSubscriber,
    emf_emitter::EmfEmitter,
    emf_sink::EmfSink,
    record::MetricRecord,
};

// arbitrary numbered policies that won't change. We use two different policies
// to get a variety of metrics.
pub(crate) static ARBITRARY_POLICY_1: LazyLock<Policy> =
    LazyLock::new(|| Policy::from_version("20240503").unwrap());
pub(crate) static ARBITRARY_POLICY_2: LazyLock<Policy> =
    LazyLock::new(|| Policy::from_version("20190214").unwrap());

pub struct TestEndpoint<E, T> {
    pub server_config: s2n_tls::config::Config,
    pub subscriber: AggregatedMetricsSubscriber<E>,
    pub exporter: T,
}

impl<E, T> TestEndpoint<E, T> {
    pub fn client_handshake(&self, client_policy: &Policy) -> TestPair {
        let client_config = build_config(client_policy).unwrap();
        let mut pair = TestPair::from_configs(&client_config, &self.server_config);
        pair.handshake().unwrap();
        pair
    }
}

impl TestEndpoint<Sender<MetricRecord>, Receiver<MetricRecord>> {
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

/// Shared buffer for capturing EMF output in tests.
#[derive(Clone)]
pub(crate) struct TestBuffer {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl TestBuffer {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Take the accumulated bytes, leaving the buffer empty.
    pub fn take(&self) -> Vec<u8> {
        std::mem::take(&mut *self.inner.lock().unwrap())
    }
}

impl EmfSink for TestBuffer {
    fn write_record(&self, record: &[u8]) -> std::io::Result<()> {
        let mut buf = self.inner.lock().unwrap();
        buf.extend_from_slice(record);
        Ok(())
    }
}

impl TestEndpoint<EmfEmitter<TestBuffer>, TestBuffer> {
    pub fn new_emf(resource: &str, policy: &Policy) -> Self {
        let buffer = TestBuffer::new();
        let emitter = EmfEmitter::new("test_server".to_owned(), buffer.clone());
        let subscriber =
            AggregatedMetricsSubscriber::with_resource_name(emitter, resource);

        let server_config = {
            let mut config = config_builder(policy).unwrap();
            config.set_event_subscriber(subscriber.clone()).unwrap();
            config.build().unwrap()
        };

        Self {
            server_config,
            subscriber,
            exporter: buffer,
        }
    }
}
