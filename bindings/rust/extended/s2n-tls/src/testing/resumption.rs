// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use crate::{
        callbacks::{SessionTicket, SessionTicketCallback},
        config::ConnectionInitializer,
        connection::{self, Connection},
        testing::*,
    };
    use futures_test::task::noop_waker;
    use std::{error::Error, sync::Mutex, time::SystemTime};

    #[derive(Default, Clone)]
    pub struct SessionTicketHandler {
        stored_ticket: Arc<Mutex<Option<Vec<u8>>>>,
    }

    // Implement the session ticket callback that stores the SessionTicket type
    impl SessionTicketCallback for SessionTicketHandler {
        fn on_session_ticket(
            &self,
            _connection: &mut connection::Connection,
            session_ticket: &SessionTicket,
        ) {
            let size = session_ticket.len().unwrap();
            let mut data = vec![0; size];
            session_ticket.data(&mut data).unwrap();
            let mut ptr = (*self.stored_ticket).lock().unwrap();
            if ptr.is_none() {
                *ptr = Some(data);
            }
        }
    }

    impl ConnectionInitializer for SessionTicketHandler {
        fn initialize_connection(
            &self,
            connection: &mut crate::connection::Connection,
        ) -> crate::callbacks::ConnectionFutureResult {
            if let Some(ticket) = (*self.stored_ticket).lock().unwrap().as_deref() {
                connection.set_session_ticket(ticket)?;
            }
            Ok(None)
        }
    }

    // Create test ticket key
    const KEY: [u8; 16] = [0; 16];
    const KEYNAME: [u8; 3] = [1, 3, 4];

    fn validate_session_ticket(conn: &Connection) -> Result<(), Box<dyn Error>> {
        assert!(conn.session_ticket_length()? > 0);
        let mut session = vec![0; conn.session_ticket_length()?];
        //load the ticket and make sure session is no longer empty
        assert_eq!(
            conn.session_ticket(&mut session)?,
            conn.session_ticket_length()?
        );
        assert_ne!(session, vec![0; conn.session_ticket_length()?]);
        Ok(())
    }

    #[test]
    fn resume_tls12_session() -> Result<(), Box<dyn Error>> {
        let keypair = CertKeyPair::default();

        // Initialize config for server with a ticket key
        let mut server_config_builder = Builder::new();
        server_config_builder
            .add_session_ticket_key(&KEYNAME, &KEY, SystemTime::now())?
            .set_security_policy(&security::TESTING_TLS12)?
            .load_pem(keypair.cert(), keypair.key())?;
        let server_config = server_config_builder.build()?;

        let handler = SessionTicketHandler::default();

        // create config for client
        let mut client_config_builder = Builder::new();

        client_config_builder
            .enable_session_tickets(true)?
            .set_session_ticket_callback(handler.clone())?
            .trust_pem(keypair.cert())?
            .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?
            .set_security_policy(&security::TESTING_TLS12)?
            .set_connection_initializer(handler)?;
        let client_config = client_config_builder.build()?;

        // initial handshake, no resumption
        {
            let mut pair = TestPair::from_configs(&client_config, &server_config);
            // Client needs a waker due to its use of an async callback
            pair.client.set_waker(Some(&noop_waker()))?;
            pair.handshake()?;

            // Check connection was full handshake and a session ticket was included
            assert!(!pair.client.resumed());
            validate_session_ticket(&pair.client)?;
        }

        // the first handshake yielded a session ticket, so the second handshake
        // should be able to use resumption
        {
            let mut pair = TestPair::from_configs(&client_config, &server_config);
            // Client needs a waker due to its use of an async callback
            pair.client.set_waker(Some(&noop_waker()))?;
            pair.handshake()?;
            // Check new connection was resumed
            assert!(pair.client.resumed());
            // validate that a ticket is available
            validate_session_ticket(&pair.client)?;
            validate_session_ticket(&pair.server)?;
        }

        Ok(())
    }

    #[test]
    fn resume_tls13_session() -> Result<(), Box<dyn Error>> {
        let keypair = CertKeyPair::default();

        // Initialize config for server with a ticket key
        let mut server_config_builder = Builder::new();
        server_config_builder
            .add_session_ticket_key(&KEYNAME, &KEY, SystemTime::now())?
            .load_pem(keypair.cert(), keypair.key())?
            .set_security_policy(&security::DEFAULT_TLS13)?;
        let server_config = server_config_builder.build()?;

        let handler = SessionTicketHandler::default();

        // create config for client
        let mut client_config_builder = Builder::new();
        client_config_builder
            .enable_session_tickets(true)?
            .set_session_ticket_callback(handler.clone())?
            .set_connection_initializer(handler)?
            .trust_pem(keypair.cert())?
            .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?
            .set_security_policy(&security::DEFAULT_TLS13)?;
        let client_config = client_config_builder.build()?;

        // 1st handshake: no session ticket, so no resumption
        // 2nd handshake: should be able to use the session ticket from the first
        //                handshake (stored on the config) to resume
        for expected_resumption in [false, true] {
            let mut pair = TestPair::from_configs(&client_config, &server_config);
            // Client needs a waker due to its use of an async callback
            pair.client.set_waker(Some(&noop_waker()))?;
            pair.handshake()?;

            // Do a recv call on the client side to read a session ticket. Poll function
            // returns pending since no application data was read, however it is enough
            // to collect the session ticket.
            assert!(pair.client.poll_recv(&mut [0]).is_pending());

            // assert the resumption status
            assert_eq!(pair.client.resumed(), expected_resumption);

            // validate that a ticket is available
            validate_session_ticket(&pair.client)?;
        }
        Ok(())
    }

    // Test that a genuine TLS1.3 session ticket is not accepted on the
    // TLS1.2 resumption path.
    //
    // The honest s2n client never places a TLS1.3 ticket in the legacy TLS1.2
    // SessionTicket extension, so we model the malicious client directly: we craft
    // a serialized session that makes a TLS1.2 client (a) carry the genuine 138-byte
    // TLS1.3 ticket as its client_ticket (sent in the legacy extension) and (b) use
    // an all-zero master secret, matching what the confused server will derive.
    #[test]
    fn tls13_ticket_on_tls12_path() -> Result<(), Box<dyn Error>> {
        const S2N_STATE_WITH_SESSION_TICKET: u8 = 1;
        const S2N_SERIALIZED_FORMAT_TLS12_V3: u8 = 4;
        const S2N_TLS12: u8 = 33;
        // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (the suite the RSA cert + 20240331 prefs negotiate).
        const TLS12_CIPHER: [u8; 2] = [0xC0, 0x2F];

        let keypair = CertKeyPair::default();

        // Server allows both TLS1.2 and TLS1.3 (the common/default case) and holds
        // the ticket key used to issue the TLS1.3 ticket.
        let mut server_config_builder = Builder::new();
        server_config_builder
            .add_session_ticket_key(&KEYNAME, &KEY, SystemTime::now())?
            .set_security_policy(&security::DEFAULT_TLS13)?
            .load_pem(keypair.cert(), keypair.key())?;
        let server_config = server_config_builder.build()?;

        // Step 1: obtain a genuine server-issued TLS1.3 ticket via a normal handshake.
        let handler = SessionTicketHandler::default();
        let mut tls13_client_builder = Builder::new();
        tls13_client_builder
            .enable_session_tickets(true)?
            .set_session_ticket_callback(handler.clone())?
            .set_connection_initializer(handler.clone())?
            .trust_pem(keypair.cert())?
            .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?
            .set_security_policy(&security::DEFAULT_TLS13)?;
        let tls13_client_config = tls13_client_builder.build()?;
        {
            let mut pair = TestPair::from_configs(&tls13_client_config, &server_config);
            pair.client.set_waker(Some(&noop_waker()))?;
            pair.handshake()?;
            assert!(pair.client.poll_recv(&mut [0]).is_pending());
        }

        // The callback stored the full serialized session:
        //   [format=WITH_SESSION_TICKET][ticket_len:u16][ticket bytes...][tls13 state...]
        // Extract just the raw ticket bytes.
        let full_session = handler
            .stored_ticket
            .lock()
            .unwrap()
            .clone()
            .expect("no ticket captured");
        assert_eq!(full_session[0], S2N_STATE_WITH_SESSION_TICKET);
        let ticket_len = u16::from_be_bytes([full_session[1], full_session[2]]) as usize;
        let ticket = &full_session[3..3 + ticket_len];
        assert_eq!(
            ticket.len(),
            138,
            "default TLS1.3 ticket should be 138 bytes"
        );

        // Step 2: craft a TLS1.2 client session that carries this TLS1.3 ticket and a
        // zero master secret.
        let mut crafted = Vec::new();
        crafted.push(S2N_STATE_WITH_SESSION_TICKET);
        crafted.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
        crafted.extend_from_slice(ticket);
        // TLS1.2 V3 outer state:
        crafted.push(S2N_SERIALIZED_FORMAT_TLS12_V3);
        crafted.push(S2N_TLS12);
        crafted.extend_from_slice(&TLS12_CIPHER);
        crafted.extend_from_slice(&0u64.to_be_bytes()); // issue time
        crafted.extend_from_slice(&[0u8; 48]); // all-zero master secret
        crafted.push(0); // ems_negotiated

        // Malicious TLS1.2 client: force TLS1.2 so the ticket goes in the legacy
        // SessionTicket extension.
        let mut attacker_builder = Builder::new();
        attacker_builder
            .enable_session_tickets(true)?
            .trust_pem(keypair.cert())?
            .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?
            .set_security_policy(&security::TESTING_TLS12)?;
        let attacker_config = attacker_builder.build()?;

        use crate::connection::Builder as _;
        let mut attacker = attacker_config.build_connection(crate::enums::Mode::Client)?;
        attacker.set_session_ticket(&crafted)?;

        let server = server_config.build_connection(crate::enums::Mode::Server)?;
        let mut pair = TestPair::from_connections(attacker, server);
        pair.client.set_waker(Some(&noop_waker()))?;

        pair.handshake().expect("handshake should complete");
        assert_eq!(
            pair.server.actual_protocol_version()?,
            crate::enums::Version::TLS12
        );
        assert!(
            !pair.server.resumed(),
            "server should not have accepted this session ticket"
        );
        assert!(
            !pair.client.resumed(),
            "client should have negotiated full handshake"
        );

        Ok(())
    }
}
