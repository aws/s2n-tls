// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use crate::{
        callbacks::{SessionTicket, SessionTicketCallback},
        connection,
        testing::{s2n_tls::*, *},
    };
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

    // Create test ticket key
    const KEY: [u8; 16] = [0; 16];
    const KEYNAME: [u8; 3] = [1, 3, 4];

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
            .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;
        let client_config = client_config_builder.build()?;

        // create and configure a server connection
        let mut server = connection::Connection::new_server();
        server
            .set_config(server_config.clone())
            .expect("Failed to bind config to server connection");

        // create a client connection
        let mut client = connection::Connection::new_client();
        client
            .set_config(client_config.clone())
            .expect("Unable to set client config");

        let server = Harness::new(server);
        let client = Harness::new(client);
        let pair = Pair::new(server, client);
        let pair = poll_tls_pair(pair);

        let client = pair.client.0.connection();

        // Check connection was full handshake and a session ticket was included
        assert_eq!(
            client.handshake_type()?,
            "NEGOTIATED|FULL_HANDSHAKE|TLS12_PERFECT_FORWARD_SECRECY|WITH_SESSION_TICKET"
        );

        // create and configure a client/server connection again
        let mut server = connection::Connection::new_server();
        server
            .set_config(server_config)
            .expect("Failed to bind config to server connection");

        // create a client connection with a resumption ticket
        let mut client = connection::Connection::new_client();

        let ticket = (*handler.stored_ticket)
            .lock()
            .unwrap()
            .clone()
            .expect("Ticket should not be None");
        client
            .set_session_ticket(&ticket)?
            .set_config(client_config)
            .expect("Unable to set client config");

        let server = Harness::new(server);
        let client = Harness::new(client);
        let pair = Pair::new(server, client);
        let pair = poll_tls_pair(pair);

        let client = pair.client.0.connection();

        // Check new connection was resumed
        assert_eq!(client.handshake_type()?, "NEGOTIATED");
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
            .set_config(client_config.clone())
            .expect("Unable to set client config");

        let server = Harness::new(server);
        let client = Harness::new(client);
        let pair = Pair::new(server, client);
        let mut pair = poll_tls_pair(pair);

        // Do a recv call on the client side to read a session ticket. Poll function
        // returns pending since no application data was read, however it is enough
        // to collect the session ticket.
        let mut recv_buffer: [u8; 10] = [0; 10];
        assert!(pair.poll_recv(Mode::Client, &mut recv_buffer).is_pending());

        let client = pair.client.0.connection();
        // Check connection was full handshake
        assert_eq!(
            client.handshake_type()?,
            "NEGOTIATED|FULL_HANDSHAKE|MIDDLEBOX_COMPAT"
        );

        // create and configure a client/server connection again
        let mut server = connection::Connection::new_server();
        server
            .set_config(server_config)
            .expect("Failed to bind config to server connection");

        let ticket = (*handler.stored_ticket)
            .lock()
            .unwrap()
            .clone()
            .expect("Ticket should not be None");

        // create a client connection with a resumption ticket
        let mut client = connection::Connection::new_client();
        client
            .set_session_ticket(&ticket)?
            .set_config(client_config)
            .expect("Unable to set client config");

        let server = Harness::new(server);
        let client = Harness::new(client);
        let pair = Pair::new(server, client);
        let pair = poll_tls_pair(pair);

        let client = pair.client.0.connection();

        // Check new connection was resumed
        assert_eq!(client.handshake_type()?, "NEGOTIATED|MIDDLEBOX_COMPAT");
        Ok(())
    }
}
