use crate::harness::{TlsImpl, Buffer};
use rustls::{
    Certificate, ClientConfig, ClientConnection, Connection, PrivateKey, RootCertStore,
    ServerConfig, ServerConnection, ServerName,
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{io::Read, pin::Pin, sync::Arc};
use std::io::Write;

pub struct Rustls {
    c_to_s_buf: Pin<Box<Buffer>>,
    s_to_c_buf: Pin<Box<Buffer>>,
    c_config: Arc<ClientConfig>,
    s_config: Arc<ServerConfig>,
    c_conn: Connection,
    s_conn: Connection
}

impl Rustls {
    fn get_root_cert() -> Certificate {
        Certificate(
            certs(&mut include_bytes!("certs-quic/certs/ca-cert.pem").as_ref())
                .unwrap()
                .remove(0),
        )
    }

    fn get_root_cert_store() -> RootCertStore {
        let mut root_certs = RootCertStore::empty();
        root_certs.add(&Rustls::get_root_cert()).unwrap();
        root_certs
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

    fn create_client_config() -> Arc<ClientConfig> {
        Arc::new(
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(Self::get_root_cert_store())
                .with_no_client_auth()
        )
    }
    fn create_server_config() -> Arc<ServerConfig> {
        Arc::new(
            ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(Rustls::get_cert_chain(), Rustls::get_server_key())
                .unwrap()
        )
    }

    fn transfer<T: Read+Write>(left: &mut Connection, right: &mut Connection, buf: &mut T) {
        let source = match &left {
            Connection::Client(_) => "Client",
            Connection::Server(_) => "Server",
        };

        //println!("{source} {}", if left.wants_write() { "wants write" } else { "doesn't want write" });

        while left.wants_write() {
            let size = left.write_tls(buf).unwrap();
            if size == 0 {
                return;
            }
            println!("{source} sending {size} bytes");

            let mut offset = 0;
            while offset != size {
                offset += right.read_tls(buf).unwrap();
            }

            //println!("{source} sent {buf:x?}");
        }
    }

    fn get_mut(buf: &mut Buffer) -> &mut Buffer {
        buf
    }
}

impl TlsImpl for Rustls {
    fn new() -> Self {
        let server_name = ServerName::try_from("localhost").unwrap();
        let c_config = Self::create_client_config();
        let s_config = Self::create_server_config();
        let client_conn = ClientConnection::new(c_config, server_name).unwrap();
        let server_conn = ServerConnection::new(s_config).unwrap();
        Rustls {
            c_to_s_buf: Box::pin(Buffer::new()),
            s_to_c_buf: Box::pin(Buffer::new()),
            c_config: Self::create_client_config(),
            s_config: Self::create_server_config(),
            c_conn: Connection::Client(client_conn),
            s_conn: Connection::Server(server_conn),
        }
    }
    fn handshake(&mut self) -> &mut Self {
        let mut max_iter = 1000;
        while (self.c_conn.is_handshaking() || self.s_conn.is_handshaking()) && max_iter > 0 {
            //let test = self.c_to_s_buf;
            Rustls::transfer(&mut self.c_conn, &mut self.s_conn, Self::get_mut(&mut self.c_to_s_buf));
            self.s_conn.process_new_packets().unwrap();
            Rustls::transfer(&mut self.s_conn, &mut self.c_conn, Self::get_mut(&mut self.s_to_c_buf));
            self.c_conn.process_new_packets().unwrap();
            max_iter -= 1;
        }

        println!("{}", self.c_conn.is_handshaking() || self.s_conn.is_handshaking());
        self
    }
}
