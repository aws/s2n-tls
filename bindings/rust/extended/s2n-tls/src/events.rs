// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{ffi::CStr, fmt::Debug, time::Duration};

use crate::connection::Connection;

pub struct HandshakeEvent<'a>(&'a s2n_tls_sys::s2n_event_handshake);

/// The outcome of a handshake: either success with negotiated parameters,
/// or failure with error information.
pub enum HandshakeResult<'a> {
    Success(HandshakeSuccess<'a>),
    Failure(HandshakeFailure<'a>),
}

/// Negotiated parameters available after a successful handshake.
pub struct HandshakeSuccess<'a>(&'a s2n_tls_sys::s2n_event_handshake);

/// Error information available after a failed handshake.
pub struct HandshakeFailure<'a>(&'a s2n_tls_sys::s2n_event_handshake);

impl<'a> HandshakeEvent<'a> {
    pub(crate) fn new(event: &'a s2n_tls_sys::s2n_event_handshake) -> Self {
        Self(event)
    }

    /// The security policy label for the connection.
    pub fn security_policy_label(&self) -> &'static str {
        maybe_string(self.0.security_policy_label).unwrap_or("unknown")
    }

    /// Handshake duration, which includes network latency and waiting for the peer.
    pub fn duration(&self) -> Duration {
        Duration::from_nanos(self.0.handshake_end_ns - self.0.handshake_start_ns)
    }

    /// Handshake time, which is just the amount of time synchronously spent in s2n_negotiate.
    ///
    /// This is roughly the "cpu cost" of the handshake.
    pub fn synchronous_time(&self) -> Duration {
        Duration::from_nanos(self.0.handshake_time_ns)
    }

    /// Returns the outcome of the handshake, providing access to either the
    /// negotiated parameters (on success) or error information (on failure).
    pub fn result(&self) -> HandshakeResult<'a> {
        if self.0.error_code == 0 {
            HandshakeResult::Success(HandshakeSuccess(self.0))
        } else {
            HandshakeResult::Failure(HandshakeFailure(self.0))
        }
    }

    #[deprecated(note = "will be removed with the release of subscriber 0.0.5")]
    pub fn protocol_version(&self) -> crate::enums::Version {
        HandshakeSuccess(self.0).protocol_version()
    }

    #[deprecated(note = "will be removed with the release of subscriber 0.0.5")]
    pub fn cipher(&self) -> &'static str {
        HandshakeSuccess(self.0).cipher()
    }

    #[deprecated(note = "will be removed with the release of subscriber 0.0.5")]
    pub fn group(&self) -> Option<&'static str> {
        HandshakeSuccess(self.0).group()
    }
}

impl HandshakeSuccess<'_> {
    /// Return the negotiated protocol version on the connection.
    pub fn protocol_version(&self) -> crate::enums::Version {
        self.0.protocol_version.try_into().unwrap()
    }

    /// The negotiated cipher, in IANA format.
    pub fn cipher(&self) -> &'static str {
        maybe_string(self.0.cipher).unwrap()
    }

    /// The negotiated key exchange group, in IANA format.
    ///
    /// None in the case of RSA key exchange or TLS 1.2 session resumption.
    pub fn group(&self) -> Option<&'static str> {
        let group = maybe_string(self.0.group)?;
        if group == "NONE" {
            None
        } else {
            Some(group)
        }
    }
}

impl HandshakeFailure<'_> {
    /// The s2n error code for the handshake failure.
    pub fn error_code(&self) -> i32 {
        self.0.error_code
    }
}

impl Debug for HandshakeEvent<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("HandshakeEvent");
        s.field("security_policy_label", &self.security_policy_label())
            .field("duration", &self.duration())
            .field("synchronous_time", &self.synchronous_time());
        match self.result() {
            HandshakeResult::Success(success) => {
                s.field("protocol_version", &success.protocol_version())
                    .field("cipher", &success.cipher())
                    .field("group", &success.group());
            }
            HandshakeResult::Failure(failure) => {
                s.field("error_code", &failure.error_code());
            }
        }
        s.finish()
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
    use std::ffi::CStr;

    use crate::{
        enums::Version, error::Error as S2NError, security::DEFAULT_TLS13,
        testing::LIFOSessionResumption,
    };
    use std::{
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, Mutex,
        },
        task::Poll,
        time::SystemTime,
    };

    use super::*;
    use crate::{
        security::{self, Policy},
        testing::{build_config, config_builder, TestPair},
    };

    #[derive(Debug)]
    struct ExpectedSuccess {
        cipher: &'static str,
        group: Option<&'static str>,
        protocol: crate::enums::Version,
        security_policy_label: &'static str,
    }

    #[derive(Debug, Default)]
    pub struct TestSubscriber {
        invoked: Arc<AtomicU64>,
        expected: Arc<Mutex<Option<ExpectedSuccess>>>,
    }

    impl ExpectedSuccess {
        fn assert_matches(&self, event: &HandshakeEvent) {
            let success = match event.result() {
                HandshakeResult::Success(s) => s,
                HandshakeResult::Failure(_) => panic!("expected success, got failure"),
            };
            assert_eq!(self.cipher, success.cipher());
            assert_eq!(self.group, success.group());
            assert_eq!(self.protocol, success.protocol_version());
            assert_eq!(self.security_policy_label, event.security_policy_label());
        }
    }

    impl TestSubscriber {
        fn set_expected(&self, event: ExpectedSuccess) {
            *self.expected.lock().unwrap() = Some(event);
        }
    }

    impl EventSubscriber for TestSubscriber {
        fn on_handshake_event(&self, _conn: &Connection, event: &HandshakeEvent) {
            assert!(event.synchronous_time() <= event.duration());
            let expected = self.expected.lock().unwrap();
            if let Some(expected) = expected.as_ref() {
                expected.assert_matches(event);
            }
            self.invoked
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[test]
    fn tls13_handshake() -> Result<(), S2NError> {
        const EXPECTED: ExpectedSuccess = ExpectedSuccess {
            cipher: "TLS_AES_128_GCM_SHA256",
            group: Some("X25519MLKEM768"),
            protocol: Version::TLS13,
            security_policy_label: "default",
        };

        let subscriber = TestSubscriber::default();
        let invoked = subscriber.invoked.clone();
        subscriber.set_expected(EXPECTED);

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
        const EXPECTED: ExpectedSuccess = ExpectedSuccess {
            cipher: "AES128-SHA256",
            group: None,
            protocol: Version::TLS12,
            security_policy_label: "20140601",
        };
        // 20140601 only support DHE and RSA kx. We don't load any DHE params, so
        // it only supports RSA kx.
        let rsa_kx_policy = Policy::from_version("20140601")?;

        let subscriber = TestSubscriber::default();
        let invoked = subscriber.invoked.clone();
        subscriber.set_expected(EXPECTED);

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
        const FULL_HS: ExpectedSuccess = ExpectedSuccess {
            cipher: "ECDHE-RSA-AES128-GCM-SHA256",
            group: Some("secp256r1"),
            protocol: Version::TLS12,
            security_policy_label: "ELBSecurityPolicy-TLS-1-0-2015-04",
        };
        const RESUMPTION: ExpectedSuccess = ExpectedSuccess {
            cipher: "ECDHE-RSA-AES128-GCM-SHA256",
            group: None,
            protocol: Version::TLS12,
            security_policy_label: "ELBSecurityPolicy-TLS-1-0-2015-04",
        };

        let subscriber = TestSubscriber::default();
        let invoked = subscriber.invoked.clone();
        let expected = subscriber.expected.clone();
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
        *expected.lock().unwrap() = Some(FULL_HS);
        {
            let mut test_pair = TestPair::from_configs(&client_config, &server_config);
            test_pair.client.set_waker(Some(&noop_waker()))?;
            test_pair.handshake().unwrap();
            assert_eq!(invoked.load(Ordering::Relaxed), 1);
        }

        // session resumption: there is no additional ECDHE in TLS 1.2 session
        // resumption, so no group is recorded.
        *expected.lock().unwrap() = Some(RESUMPTION);
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

    /// A handshake event is emitted in the case of failure, with error information.
    #[test]
    fn failure_event() -> Result<(), S2NError> {
        #[derive(Debug, Default)]
        struct TestErrorSubscriber {
            error_code: Arc<Mutex<Option<i32>>>,
        }

        impl EventSubscriber for TestErrorSubscriber {
            fn on_handshake_event(&self, _conn: &Connection, event: &HandshakeEvent) {
                if let HandshakeResult::Failure(failure) = event.result() {
                    *self.error_code.lock().unwrap() = Some(failure.error_code());
                }
            }
        }

        let subscriber = TestErrorSubscriber::default();
        let error_code = subscriber.error_code.clone();

        let server_config = {
            // doesn't allow TLS 1.3
            let mut builder = config_builder(&Policy::from_version("20141001")?).unwrap();
            builder.set_event_subscriber(subscriber)?;
            builder.build()?
        };

        // only allows TLS 1.3
        let client_config = build_config(&DEFAULT_TLS13).unwrap();

        let mut pair = TestPair::from_configs(&client_config, &server_config);
        // Drive the client first to send the ClientHello, then the server
        // to process it and fail.
        pair.server.set_waker(Some(&noop_waker()))?;
        let _ = pair.client.poll_negotiate();
        let server_err = match pair.server.poll_negotiate() {
            Poll::Ready(Err(e)) => e,
            other => panic!("expected server failure, got {:?}", other),
        };

        let code = error_code
            .lock()
            .unwrap()
            .expect("failure event was emitted");
        let event_error_name = unsafe {
            CStr::from_ptr(s2n_tls_sys::s2n_strerror_name(code))
                .to_str()
                .unwrap()
        };
        assert_eq!(event_error_name, server_err.name());

        Ok(())
    }
}
