// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use crate::{
        callbacks::{SessionTicket, SessionTicketCallback},
        config::ConnectionInitializer,
        connection::{self, Connection},
        testing::{s2n_tls::*, *},
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
    fn resume_session() -> Result<(), Box<dyn Error>> {
        let keypair = CertKeyPair::default();

        // Initialize config for server with a ticket key
        let mut server_config_builder = Builder::new();
        server_config_builder
            .add_session_ticket_key(&KEYNAME, &KEY, SystemTime::now())?
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

        // create and configure a server connection
        let mut server = connection::Connection::new_server();
        server
            .set_config(server_config.clone())
            .expect("Failed to bind config to server connection");

        // create a client connection
        let mut client = connection::Connection::new_client();
        client
            .set_waker(Some(&noop_waker()))?
            .set_config(client_config.clone())
            .expect("Unable to set client config");

        let server = Harness::new(server);
        let client = Harness::new(client);
        let pair = Pair::new(server, client);
        let mut pair = poll_tls_pair(pair);

        // Do a recv call on the client side to read a session ticket. Poll function
        // returns pending since no application data was read, however it is enough
        // to collect the session ticket.
        assert!(pair.poll_recv(Mode::Client, &mut [0]).is_pending());

        let client = pair.client.0.connection();
        // Check connection was full handshake
        assert!(!client.resumed());
        // validate that a ticket is available
        validate_session_ticket(client)?;

        // create and configure a client/server connection again
        let mut server = connection::Connection::new_server();
        server
            .set_config(server_config)
            .expect("Failed to bind config to server connection");

        // create a client connection with a resumption ticket
        let mut client = connection::Connection::new_client();
        client
            .set_waker(Some(&noop_waker()))?
            .set_config(client_config)
            .expect("Unable to set client config");

        let server = Harness::new(server);
        let client = Harness::new(client);
        let pair = Pair::new(server, client);
        let mut pair = poll_tls_pair(pair);

        // Do a recv call on the client side to read a session ticket. Poll function
        // returns pending since no application data was read, however it is enough
        // to collect the session ticket.
        assert!(pair.poll_recv(Mode::Client, &mut [0]).is_pending());

        let client = pair.client.0.connection();
        // Check new connection was resumed
        assert!(client.resumed());
        // validate that a ticket is available
        validate_session_ticket(client)?;
        Ok(())
    }
}
