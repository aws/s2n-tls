use crate::harness::TlsImpl;
use rustls::{
    Certificate, ClientConfig, ClientConnection, Connection, PrivateKey, RootCertStore,
    ServerConfig, ServerConnection, ServerName,
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{io::Read, sync::Arc};

pub struct Rustls;

impl Rustls {
    fn get_root_cert() -> Certificate {
        Certificate(
            certs(&mut include_bytes!("certs-quic/certs/ca-cert.pem").as_ref())
                .unwrap()
                .remove(0),
        )
    }

    fn get_cert_chain() -> Vec<Certificate> {
        let chain = certs(&mut include_bytes!("certs-quic/certs/fullchain.pem").as_ref()).unwrap();
        chain
            .iter()
            .map(|bytes| Certificate(bytes.to_vec()))
            .collect()
    }

    fn get_server_key() -> PrivateKey {
        PrivateKey(
            pkcs8_private_keys(&mut include_bytes!("certs-quic/certs/server-key.pem").as_ref())
                .unwrap()
                .remove(0),
        )
    }

    fn transfer(left: &mut Connection, right: &mut Connection, buf: &mut [u8]) {
        let source = match &left {
            Connection::Client(_) => "Client",
            Connection::Server(_) => "Server",
        };

        //println!("{source} {}", if left.wants_write() { "wants write" } else { "doesn't want write" });

        while left.wants_write() {
            let size = left.write_tls(&mut buf.as_mut()).unwrap();
            if size == 0 {
                return;
            }
            println!("{source} sending {size} bytes");

            let mut offset = 0;
            &mut buf.as_ref() as &mut dyn Read;
            while offset != size {
                offset += right.read_tls(&mut buf[offset..size].as_ref()).unwrap();
            }

            //println!("{source} sent {buf:x?}");
        }
    }
}

impl TlsImpl for Rustls {
    fn handshake() {
        let mut buffer = [0u8; 100000];

        let server_name = ServerName::try_from("localhost").unwrap();
        let mut root_certs = RootCertStore::empty();
        root_certs.add(&Rustls::get_root_cert()).unwrap();

        let client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_certs)
            .with_no_client_auth();
        let client_conn = ClientConnection::new(Arc::new(client_config), server_name).unwrap();
        let mut client_conn = Connection::Client(client_conn);

        let server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(Rustls::get_cert_chain(), Rustls::get_server_key())
            .unwrap();
        let server_conn = ServerConnection::new(Arc::new(server_config)).unwrap();
        let mut server_conn = Connection::Server(server_conn);

        let mut max_iter = 1000;
        while (client_conn.is_handshaking() || server_conn.is_handshaking()) && max_iter > 0 {
            Rustls::transfer(&mut client_conn, &mut server_conn, &mut buffer);
            server_conn.process_new_packets().unwrap();
            Rustls::transfer(&mut server_conn, &mut client_conn, &mut buffer);
            client_conn.process_new_packets().unwrap();
            max_iter -= 1;
        }

        println!("{}", server_conn.is_handshaking());
    }
}
