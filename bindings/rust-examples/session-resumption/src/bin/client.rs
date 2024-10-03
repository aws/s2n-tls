// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{
    callbacks::{SessionTicket, SessionTicketCallback},
    connection::{Connection, ModifiedBuilder},
    security::DEFAULT_TLS13,
};
use s2n_tls_tokio::TlsConnector;
use std::{
    collections::HashMap,
    error::Error,
    net::IpAddr,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

struct ApplicationContext {
    ip_addr: IpAddr,
    tickets_received: u32,
}

#[derive(Default, Clone)]
pub struct SessionTicketHandler {
    session_tickets: Arc<Mutex<HashMap<IpAddr, Vec<u8>>>>,
}

impl SessionTicketCallback for SessionTicketHandler {
    fn on_session_ticket(&self, connection: &mut Connection, session_ticket: &SessionTicket) {
        let app_context = connection
            .application_context_mut::<ApplicationContext>()
            .unwrap();

        let size = session_ticket.len().unwrap();
        let mut data = vec![0; size];
        session_ticket.data(&mut data).unwrap();

        // Associate the received session ticket with the connection's IP address.
        let mut session_tickets = self.session_tickets.lock().unwrap();
        session_tickets.insert(app_context.ip_addr, data);

        // Indicate that the connection has received a session ticket.
        app_context.tickets_received += 1;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cert_path = format!("{}/certs/test-cert.pem", env!("CARGO_MANIFEST_DIR"));
    let cert = std::fs::read(cert_path).unwrap();

    let session_ticket_handler = SessionTicketHandler::default();

    let config = {
        let mut builder = s2n_tls::config::Builder::new();
        builder.set_security_policy(&DEFAULT_TLS13).unwrap();
        builder.trust_pem(&cert).unwrap();
        builder
            .set_session_ticket_callback(session_ticket_handler.clone())
            .unwrap();
        builder.enable_session_tickets(true).unwrap();
        builder.build()?
    };

    for connection_idx in 0..3 {
        let stream = TcpStream::connect("127.0.0.1:9000").await?;
        let ip = stream.peer_addr().unwrap().ip();

        let builder = ModifiedBuilder::new(config.clone(), |conn| {
            // Associate the IP address with the new connection.
            conn.set_application_context(ApplicationContext {
                ip_addr: ip,
                tickets_received: 0,
            });

            // If a session ticket exists that corresponds with the IP address, resume the
            // connection.
            let session_tickets = session_ticket_handler.session_tickets.lock().unwrap();
            if let Some(session_ticket) = session_tickets.get(&ip) {
                conn.set_session_ticket(session_ticket)?;
            }

            Ok(conn)
        });
        let client = TlsConnector::new(builder);

        let handshake = client.connect("127.0.0.1", stream).await;
        let mut tls = match handshake {
            Ok(tls) => tls,
            Err(e) => {
                println!("error during handshake: {e}");
                return Ok(());
            }
        };

        let mut response = String::new();
        tls.read_to_string(&mut response).await?;
        println!("server response: {response}");

        tls.shutdown().await?;

        let connection = tls.as_ref();
        if connection_idx == 0 {
            assert!(!connection.resumed());
        } else {
            assert!(connection.resumed());
            println!("connection resumed!");
        }

        let app_ctx = connection
            .application_context::<ApplicationContext>()
            .unwrap();
        assert_eq!(app_ctx.tickets_received, 1);
    }

    Ok(())
}
