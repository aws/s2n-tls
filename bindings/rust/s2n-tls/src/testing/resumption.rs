// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use crate::{
        connection,
        session_ticket::{SessionTicket, SessionTicketCallback},
        testing::{s2n_tls::*, *},
    };
    use std::{cell::RefCell, rc::Rc, time::Duration};

    // Creates session ticket callback handler
    #[derive(Default, Clone)]
    pub struct SessionTicketRawBytesHandler {
        stored_ticket: Rc<RefCell<Vec<u8>>>,
    }

    // Implement the session ticket callback
    impl SessionTicketCallback for SessionTicketRawBytesHandler {
        fn on_session_ticket(
            &self,
            _connection: &mut connection::Connection,
            session_ticket: SessionTicket,
        ) {
            let data = session_ticket.session_data();
            (*self.stored_ticket).borrow_mut().extend(data);
            // Default ticket lifetime is 15 hours
            assert_eq!(
                session_ticket.session_lifetime().unwrap(),
                Duration::new(54000, 0)
            );
        }
    }

    #[derive(Default, Clone)]
    pub struct SessionTicketHandler {
        stored_ticket: Rc<RefCell<Option<SessionTicket>>>,
    }

    // Implement the session ticket callback that stores the SessionTicket type instead of
    // raw bytes.
    impl SessionTicketCallback for SessionTicketHandler {
        fn on_session_ticket(
            &self,
            _connection: &mut connection::Connection,
            session_ticket: SessionTicket,
        ) {
            let mut ptr = (*self.stored_ticket).borrow_mut();
            if ptr.is_none() {
                *ptr = Some(session_ticket);
            }
        }
    }

    #[test]
    fn resume_session() {
        let keypair = CertKeyPair::default();

        // Create test ticket key
        let key: [u8; 3] = [1, 2, 3];
        let keyname: [u8; 3] = [1, 3, 4];

        // Initialize config for server with a ticket key
        let mut server_config_builder = Builder::new();
        server_config_builder
            .enable_session_tickets()
            .unwrap()
            .add_session_ticket_key(&keyname, &key, 0)
            .unwrap()
            .load_pem(keypair.cert(), keypair.key())
            .unwrap();
        let server_config = server_config_builder.build().unwrap();

        let handler = SessionTicketRawBytesHandler::default();

        // create config for client
        let mut client_config_builder = Builder::new();

        client_config_builder
            .enable_session_tickets()
            .unwrap()
            .set_session_ticket_callback(handler.clone())
            .unwrap()
            .trust_pem(keypair.cert())
            .unwrap()
            .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
            .unwrap();
        let client_config = client_config_builder.build().unwrap();

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
            client.handshake_type().unwrap(),
            "NEGOTIATED|FULL_HANDSHAKE|TLS12_PERFECT_FORWARD_SECRECY|WITH_SESSION_TICKET"
        );

        // create and configure a client/server connection again
        let mut server = connection::Connection::new_server();
        server
            .set_config(server_config)
            .expect("Failed to bind config to server connection");

        // create a client connection with a resumption ticket
        let mut client = connection::Connection::new_client();

        let ticket = SessionTicket::new(handler.stored_ticket.borrow().to_vec());
        client
            .set_session_ticket(&ticket)
            .unwrap()
            .set_config(client_config)
            .expect("Unable to set client config");

        let server = Harness::new(server);
        let client = Harness::new(client);
        let pair = Pair::new(server, client);
        let pair = poll_tls_pair(pair);

        let client = pair.client.0.connection();

        // Check new connection was resumed
        assert_eq!(client.handshake_type().unwrap(), "NEGOTIATED");
    }

    #[test]
    fn resume_tls13_session() {
        let keypair = CertKeyPair::default();

        // Create test ticket key
        let key: [u8; 3] = [1, 2, 3];
        let keyname: [u8; 3] = [1, 3, 4];

        // Initialize config for server with a ticket key
        let mut server_config_builder = Builder::new();
        server_config_builder
            .enable_session_tickets()
            .unwrap()
            .add_session_ticket_key(&keyname, &key, 0)
            .unwrap()
            .load_pem(keypair.cert(), keypair.key())
            .unwrap()
            .set_security_policy(&security::DEFAULT_TLS13)
            .unwrap();
        let server_config = server_config_builder.build().unwrap();

        let handler = SessionTicketRawBytesHandler::default();

        // create config for client
        let mut client_config_builder = Builder::new();
        client_config_builder
            .enable_session_tickets()
            .unwrap()
            .set_session_ticket_callback(handler.clone())
            .unwrap()
            .trust_pem(keypair.cert())
            .unwrap()
            .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
            .unwrap()
            .set_security_policy(&security::DEFAULT_TLS13)
            .unwrap();
        let client_config = client_config_builder.build().unwrap();

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
            client.handshake_type().unwrap(),
            "NEGOTIATED|FULL_HANDSHAKE|MIDDLEBOX_COMPAT"
        );

        // create and configure a client/server connection again
        let mut server = connection::Connection::new_server();
        server
            .set_config(server_config)
            .expect("Failed to bind config to server connection");

        let ticket = SessionTicket::new(handler.stored_ticket.borrow().to_vec());
        // create a client connection with a resumption ticket
        let mut client = connection::Connection::new_client();
        client
            .set_session_ticket(&ticket)
            .unwrap()
            .set_config(client_config)
            .expect("Unable to set client config");

        let server = Harness::new(server);
        let client = Harness::new(client);
        let pair = Pair::new(server, client);
        let pair = poll_tls_pair(pair);

        let client = pair.client.0.connection();

        // Check new connection was resumed
        assert_eq!(
            client.handshake_type().unwrap(),
            "NEGOTIATED|MIDDLEBOX_COMPAT"
        );
    }

    #[test]
    fn resume_with_owned_session() {
        let keypair = CertKeyPair::default();

        // Create test ticket key
        let key: [u8; 3] = [1, 2, 3];
        let keyname: [u8; 3] = [1, 3, 4];

        // Initialize config for server with a ticket key
        let mut server_config_builder = Builder::new();
        server_config_builder
            .enable_session_tickets()
            .unwrap()
            .add_session_ticket_key(&keyname, &key, 0)
            .unwrap()
            .load_pem(keypair.cert(), keypair.key())
            .unwrap()
            .set_security_policy(&security::DEFAULT_TLS13)
            .unwrap();
        let server_config = server_config_builder.build().unwrap();

        let handler = SessionTicketHandler::default();

        // create config for client
        let mut client_config_builder = Builder::new();
        client_config_builder
            .enable_session_tickets()
            .unwrap()
            .set_session_ticket_callback(handler.clone())
            .unwrap()
            .trust_pem(keypair.cert())
            .unwrap()
            .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
            .unwrap()
            .set_security_policy(&security::DEFAULT_TLS13)
            .unwrap();
        let client_config = client_config_builder.build().unwrap();

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
            client.handshake_type().unwrap(),
            "NEGOTIATED|FULL_HANDSHAKE|MIDDLEBOX_COMPAT"
        );

        // create and configure a client/server connection again
        let mut server = connection::Connection::new_server();
        server
            .set_config(server_config)
            .expect("Failed to bind config to server connection");

        // create a client connection with a resumption ticket
        let mut client = connection::Connection::new_client();
        client
            .set_session_ticket((*handler.stored_ticket.borrow()).as_ref().unwrap())
            .unwrap()
            .set_config(client_config)
            .expect("Unable to set client config");

        let server = Harness::new(server);
        let client = Harness::new(client);
        let pair = Pair::new(server, client);
        let pair = poll_tls_pair(pair);

        let client = pair.client.0.connection();

        // Check new connection was resumed
        assert_eq!(
            client.handshake_type().unwrap(),
            "NEGOTIATED|MIDDLEBOX_COMPAT"
        );
    }
}
