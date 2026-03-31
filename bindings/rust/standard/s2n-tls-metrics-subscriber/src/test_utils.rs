// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, LazyLock, Mutex};

use s2n_tls::{
    security::{DEFAULT_TLS13, Policy},
    testing::{TestPair, build_config, config_builder},
};

use crate::{
    AggregatedMetricsSubscriber, attribution::Attribution, format::SerializationFormat, sink::Sink,
};

pub(crate) static ARBITRARY_POLICY_1: LazyLock<Policy> =
    LazyLock::new(|| Policy::from_version("20240503").unwrap());
pub(crate) static ARBITRARY_POLICY_2: LazyLock<Policy> =
    LazyLock::new(|| Policy::from_version("20190214").unwrap());

/// A test helper that implements [`Sink`] by collecting serialized bytes into a Vec.
#[derive(Debug, Clone)]
pub(crate) struct VecSink {
    pub(crate) records: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl VecSink {
    pub(crate) fn new() -> Self {
        Self {
            records: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Sink for VecSink {
    fn write_record(&self, record: &[u8]) -> std::io::Result<()> {
        self.records.lock().unwrap().push(record.to_vec());
        Ok(())
    }
}

pub(crate) struct TestEndpoint<S: Sink> {
    pub server_config: s2n_tls::config::Config,
    pub subscriber: AggregatedMetricsSubscriber<S>,
    pub sink: S,
}

impl<S: Sink> TestEndpoint<S> {
    pub fn client_handshake(&self, client_policy: &Policy) -> TestPair {
        let client_config = build_config(client_policy).unwrap();
        let mut pair = TestPair::from_configs(&client_config, &self.server_config);
        pair.handshake().unwrap();
        pair
    }
}

impl TestEndpoint<VecSink> {
    pub fn new() -> Self {
        Self::with_format(SerializationFormat::Querylog)
    }

    pub fn with_format(format: SerializationFormat) -> Self {
        let sink = VecSink::new();
        let attribution = Attribution {
            platform: "test_server".into(),
            resource: "test_resource".into(),
        };
        let subscriber = AggregatedMetricsSubscriber::new(sink.clone(), format, attribution);
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

/// A sink that always fails, for testing error paths.
#[derive(Debug, Clone)]
pub(crate) struct FailingSink;

impl Sink for FailingSink {
    fn write_record(&self, _record: &[u8]) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "simulated sink failure",
        ))
    }
}

impl TestEndpoint<FailingSink> {
    pub fn with_failing_sink() -> Self {
        let sink = FailingSink;
        let attribution = Attribution {
            platform: "test_server".into(),
            resource: "test_resource".into(),
        };
        let subscriber = AggregatedMetricsSubscriber::new(
            sink.clone(),
            SerializationFormat::Querylog,
            attribution,
        );
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
