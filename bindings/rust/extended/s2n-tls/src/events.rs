// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{ffi::CStr, fmt::Debug, time::Duration};

use crate::connection::Connection;

pub struct HandshakeEvent<'a>(&'a s2n_tls_sys::s2n_event_handshake);

impl<'a> HandshakeEvent<'a> {
    pub(crate) fn new(event: &'a s2n_tls_sys::s2n_event_handshake) -> Self {
        Self(event)
    }

    /// Return the negotiated protocol version on the connection
    fn protocol_version(&self) -> crate::enums::Version {
        self.0.protocol_version.try_into().unwrap()
    }

    /// The negotiated cipher, in IANA format.
    fn cipher(&self) -> &'static str {
        maybe_string(self.0.cipher).unwrap()
    }

    /// The negotiated key exchange group, in IANA format.
    ///
    /// None in the case of RSA key exchange or TLS 1.2 session resumption.
    fn group(&self) -> Option<&'static str> {
        let group = maybe_string(self.0.group)?;
        if group == "NONE" {
            None
        } else {
            Some(group)
        }
    }

    /// Handshake duration, which includes network latency and waiting for the peer.
    fn duration(&self) -> Duration {
        Duration::from_nanos(self.0.handshake_end_ns - self.0.handshake_start_ns)
    }

    /// Handshake time, which is just the amount of time synchronously spent in s2n_negotiate.
    ///
    /// This is roughly the "cpu cost" of the handshake.
    fn synchronous_time(&self) -> Duration {
        Duration::from_nanos(self.0.handshake_time_ns)
    }
}

impl Debug for HandshakeEvent<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("s2n_event_handshake")
            .field("protocol_version", &self.protocol_version())
            .field("cipher", &self.cipher())
            .field("group", &self.group())
            .field("handshake_duration", &self.duration())
            .field("handshake_cpu_duration", &self.synchronous_time())
            .finish()
    }
}

fn maybe_string(string: *const libc::c_char) -> Option<&'static str> {
    if string.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(string).to_str().ok() }
    }
}

impl<A: EventSubscriber, B: EventSubscriber> EventSubscriber for (A, B) {
    fn on_handshake_event(&self, connection: &Connection, event: &HandshakeEvent) {
        self.0.on_handshake_event(connection, event);
        self.1.on_handshake_event(connection, event);
    }
}

pub trait EventSubscriber: 'static + Send + Sync {
    fn on_handshake_event(&self, connection: &Connection, event: &HandshakeEvent);
}

#[cfg(test)]
mod tests {
    use futures_test::task::noop_waker;

    use crate::{
        enums::Version, error::Error as S2NError, security::DEFAULT_TLS13,
        testing::LIFOSessionResumption,
    };
    use std::{
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, Mutex,
        },
        time::SystemTime,
    };

    use super::*;
    use crate::{
        security::{self, Policy},
        testing::{build_config, config_builder, TestPair},
    };
    #[derive(Debug)]
    struct ExpectedEvent {
        cipher: &'static str,
        group: Option<&'static str>,
        protocol: crate::enums::Version,
    }

    #[derive(Debug, Default)]
    pub struct TestSubscriber {
        invoked: Arc<AtomicU64>,
        expected_event: Arc<Mutex<Option<ExpectedEvent>>>,
    }

    impl ExpectedEvent {
        fn assert_similar(&self, event: &HandshakeEvent) {
            assert_eq!(self.cipher, event.cipher());
            assert_eq!(self.group, event.group());
            assert_eq!(self.protocol, event.protocol_version());
        }
    }

    impl TestSubscriber {
        fn set_expected_event(&self, event: ExpectedEvent) {
            let mut expected_event = self.expected_event.lock().unwrap();
            *expected_event = Some(event);
        }
    }

    impl EventSubscriber for TestSubscriber {
        fn on_handshake_event(&self, _conn: &Connection, event: &HandshakeEvent) {
            assert!(event.synchronous_time() <= event.duration());
            let expected_event = self.expected_event.lock().unwrap();
            if let Some(expected) = expected_event.as_ref() {
                expected.assert_similar(event);
            }
            self.invoked
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[test]
    fn tls13_handshake() -> Result<(), S2NError> {
        const EXPECTED_EVENT: ExpectedEvent = ExpectedEvent {
            cipher: "TLS_AES_128_GCM_SHA256",
            group: Some("X25519MLKEM768"),
            protocol: Version::TLS13,
        };

        let subscriber = TestSubscriber::default();
        let invoked = subscriber.invoked.clone();
        subscriber.set_expected_event(EXPECTED_EVENT);

        let server_config = {
            let mut builder = config_builder(&security::DEFAULT).unwrap();
            builder
                .set_event_subscriber(subscriber)?
                .add_session_ticket_key(
                    b"a key name",
                    b"good enough bytes for test",
                    SystemTime::UNIX_EPOCH,
                )?;
            builder.build()?
        };

        let client_config = {
            let session_tickets = LIFOSessionResumption::default();
            let mut builder = config_builder(&security::DEFAULT).unwrap();
            builder.enable_session_tickets(true)?;
            builder.set_session_ticket_callback(session_tickets.clone())?;
            builder.set_connection_initializer(session_tickets.clone())?;
            builder.build()?
        };

        // full handshake
        {
            let mut test_pair = TestPair::from_configs(&client_config, &server_config);
            test_pair.client.set_waker(Some(&noop_waker()))?;
            test_pair.handshake().unwrap();
            // read in session_ticket
            assert!(test_pair.client.poll_recv(&mut [0]).is_pending());
            assert_eq!(invoked.load(Ordering::Relaxed), 1);
        }

        // session resumption: group is still populated
        {
            let mut test_pair = TestPair::from_configs(&client_config, &server_config);
            test_pair.client.set_waker(Some(&noop_waker()))?;
            test_pair.handshake().unwrap();
            assert!(test_pair.client.resumed());
            assert_eq!(invoked.load(Ordering::Relaxed), 2);
        }

        Ok(())
    }

    /// When RSA key exchange is negotiated, the group is not recorded in the event
    #[test]
    fn rsa_key_exchange() -> Result<(), S2NError> {
        const EXPECTED_EVENT: ExpectedEvent = ExpectedEvent {
            cipher: "AES128-SHA256",
            group: None,
            protocol: Version::TLS12,
        };
        // 20140601 only support DHE and RSA kx. We don't load any DHE params, so
        // it only supports RSA kx.
        let rsa_kx_policy = Policy::from_version("20140601")?;

        let subscriber = TestSubscriber::default();
        let invoked = subscriber.invoked.clone();
        subscriber.set_expected_event(EXPECTED_EVENT);

        let server_config = {
            let mut builder = config_builder(&rsa_kx_policy).unwrap();
            builder.set_event_subscriber(subscriber)?;
            builder.build()?
        };
        let client_config = build_config(&rsa_kx_policy).unwrap();

        // full handshake
        let mut test_pair = TestPair::from_configs(&client_config, &server_config);
        test_pair.client.set_waker(Some(&noop_waker()))?;
        test_pair.handshake().unwrap();
        assert_eq!(invoked.load(Ordering::Relaxed), 1);

        Ok(())
    }

    #[test]
    fn tls12_handshake() -> Result<(), S2NError> {
        const FULL_HS_EVENT: ExpectedEvent = ExpectedEvent {
            cipher: "ECDHE-RSA-AES128-GCM-SHA256",
            group: Some("secp256r1"),
            protocol: Version::TLS12,
        };
        const RESUMPTION_EVENT: ExpectedEvent = ExpectedEvent {
            cipher: "ECDHE-RSA-AES128-GCM-SHA256",
            group: None,
            protocol: Version::TLS12,
        };

        let subscriber = TestSubscriber::default();
        let invoked = subscriber.invoked.clone();
        let expected_event = subscriber.expected_event.clone();
        // arbitrary policy which only allows TLS 1.2 and supports ECDHE
        let tls12_ecdhe_policy = Policy::from_version("ELBSecurityPolicy-TLS-1-0-2015-04")?;

        let server_config = {
            let mut builder = config_builder(&tls12_ecdhe_policy).unwrap();
            builder
                .set_event_subscriber(subscriber)?
                .add_session_ticket_key(
                    b"a key name",
                    b"good enough bytes for test",
                    SystemTime::UNIX_EPOCH,
                )?
                .enable_session_tickets(true)?;
            builder.build()?
        };

        let client_config = {
            let session_tickets = LIFOSessionResumption::default();
            let mut builder = config_builder(&tls12_ecdhe_policy).unwrap();
            builder.enable_session_tickets(true)?;
            builder.set_session_ticket_callback(session_tickets.clone())?;
            builder.set_connection_initializer(session_tickets.clone())?;
            builder.build()?
        };

        // full handshake: ECDHE negotiated, so group is recorded
        *expected_event.lock().unwrap() = Some(FULL_HS_EVENT);
        {
            let mut test_pair = TestPair::from_configs(&client_config, &server_config);
            test_pair.client.set_waker(Some(&noop_waker()))?;
            test_pair.handshake().unwrap();
            assert_eq!(invoked.load(Ordering::Relaxed), 1);
        }

        // session resumption: there is no additional ECDHE in TLS 1.2 session
        // resumption, so no group is recorded.
        *expected_event.lock().unwrap() = Some(RESUMPTION_EVENT);
        {
            let mut test_pair = TestPair::from_configs(&client_config, &server_config);
            test_pair.client.set_waker(Some(&noop_waker()))?;
            test_pair.handshake().unwrap();
            assert!(test_pair.client.resumed());
            assert_eq!(invoked.load(Ordering::Relaxed), 2);
        }

        Ok(())
    }

    /// handshake events are emitted from both servers and clients, and they are
    /// only emitted once per handshake event if s2n_negotiate is called multiple
    /// times.
    #[test]
    fn client_and_server_event() -> Result<(), S2NError> {
        let subscriber = TestSubscriber::default();
        let invoked = subscriber.invoked.clone();

        let subscriber_config = {
            let mut builder = config_builder(&security::DEFAULT).unwrap();
            builder.set_event_subscriber(subscriber)?;
            builder.build()?
        };

        let mut pair = TestPair::from_config(&subscriber_config);
        pair.handshake().unwrap();
        assert_eq!(invoked.load(Ordering::Relaxed), 2);

        // idempotency: calling s2n_negotiate multiple times will not send multiple
        // events
        assert!(pair.server.poll_negotiate().is_ready());
        assert!(pair.server.poll_negotiate().is_ready());
        assert_eq!(invoked.load(Ordering::Relaxed), 2);

        Ok(())
    }

    /// No handshake event is emitted in the case of failure.
    #[test]
    fn no_event_when_failure() -> Result<(), S2NError> {
        let subscriber = TestSubscriber::default();
        let invoked = subscriber.invoked.clone();

        let server_config = {
            // doesn't allow TLS 1.3
            let mut builder = config_builder(&Policy::from_version("20141001")?).unwrap();
            builder.set_event_subscriber(subscriber)?;
            builder.build()?
        };

        // only allows TLS 1.3
        let client_config = build_config(&DEFAULT_TLS13).unwrap();

        let mut pair = TestPair::from_configs(&client_config, &server_config);
        pair.handshake().unwrap_err();

        assert_eq!(invoked.load(Ordering::Relaxed), 0);
        Ok(())
    }
}
