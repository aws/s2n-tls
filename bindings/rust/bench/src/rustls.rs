use crate::{
    harness::{Buffer, Mode, TlsImpl},
    read_to_bytes, CA_CERT_PATH, SERVER_CERT_CHAIN_PATH, SERVER_KEY_PATH,
};
use log::info;
use rustls::{
    Certificate, ClientConfig, ClientConnection, Connection, PrivateKey, RootCertStore,
    ServerConfig, ServerConnection, ServerName,
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{
    io::{BufReader, Read, Write},
    sync::Arc,
};

pub struct Rustls {
    c_to_s_buf: Buffer,
    s_to_c_buf: Buffer,
    c_config: Arc<ClientConfig>,
    s_config: Arc<ServerConfig>,
    c_conn: Connection,
    s_conn: Connection,
}

impl Rustls {
    fn get_root_cert_store() -> RootCertStore {
        let root_cert = Certificate(
            certs(&mut BufReader::new(&*read_to_bytes(CA_CERT_PATH)))
                .unwrap()
                .remove(0),
        );
        let mut root_certs = RootCertStore::empty();
        root_certs.add(&root_cert).unwrap();
        root_certs
    }

    fn get_cert_chain() -> Vec<Certificate> {
        let chain = certs(&mut BufReader::new(&*read_to_bytes(SERVER_CERT_CHAIN_PATH))).unwrap();
        chain
            .iter()
            .map(|bytes| Certificate(bytes.to_vec()))
            .collect()
    }

    fn get_server_key() -> PrivateKey {
        PrivateKey(
            pkcs8_private_keys(&mut BufReader::new(&*read_to_bytes(SERVER_KEY_PATH)))
                .unwrap()
                .remove(0),
        )
    }

    fn create_client_config() -> Arc<ClientConfig> {
        Arc::new(
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(Self::get_root_cert_store())
                .with_no_client_auth(),
        )
    }
    fn create_server_config() -> Arc<ServerConfig> {
        Arc::new(
            ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(Rustls::get_cert_chain(), Rustls::get_server_key())
                .unwrap(),
        )
    }

    fn process_conn(&mut self, mode: Mode) {
        let (conn_str, conn, read_buf, write_buf);
        match mode {
            Mode::Client => {
                conn_str = "Client";
                conn = &mut self.c_conn;
                read_buf = &mut self.s_to_c_buf;
                write_buf = &mut self.c_to_s_buf;
            }
            Mode::Server => {
                conn_str = "Server";
                conn = &mut self.s_conn;
                read_buf = &mut self.c_to_s_buf;
                write_buf = &mut self.s_to_c_buf;
            }
        }

        info!("{conn_str}:");
        let mut len;
        while !read_buf.is_empty() {
            len = conn.read_tls(read_buf).unwrap();
            info!("\t- received {len}");
        }
        conn.process_new_packets().unwrap();

        while conn.wants_write() {
            len = conn.write_tls(write_buf).unwrap();
            info!("\t+ sent {len}");
        }

        write_buf.flush().unwrap();
    }
}

impl TlsImpl for Rustls {
    fn new() -> Self {
        let server_name = ServerName::try_from("localhost").unwrap();
        let c_config = Self::create_client_config();
        let s_config = Self::create_server_config();
        let client_conn = ClientConnection::new(c_config.clone(), server_name).unwrap();
        let server_conn = ServerConnection::new(s_config.clone()).unwrap();
        Rustls {
            c_to_s_buf: Buffer::new(),
            s_to_c_buf: Buffer::new(),
            c_config,
            s_config,
            c_conn: Connection::Client(client_conn),
            s_conn: Connection::Server(server_conn),
        }
    }

    fn reinit(&mut self) {
        self.c_to_s_buf.clear();
        self.s_to_c_buf.clear();
        let server_name = ServerName::try_from("localhost").unwrap();
        let client_conn = ClientConnection::new(self.c_config.clone(), server_name).unwrap();
        let server_conn = ServerConnection::new(self.s_config.clone()).unwrap();
        self.c_conn = Connection::Client(client_conn);
        self.s_conn = Connection::Server(server_conn);
    }

    fn handshake_conn(&mut self, mode: Mode) {
        self.process_conn(mode);
    }

    // fn handshake(&mut self) {
    //     if self.has_handshaked() { return; }
    //     let mut max_iter = 1000;
    //     while (self.c_conn.is_handshaking() || self.s_conn.is_handshaking()) && max_iter > 0 {
    //         self.process_conn(Mode::Client);
    //         self.process_conn(Mode::Server);
    //         max_iter -= 1;
    //     }
    //     self.has_handshaked = true;
    // }

    fn has_handshaked(&self) -> bool {
        !self.c_conn.is_handshaking() && !self.s_conn.is_handshaking()
    }

    fn bulk_transfer(&mut self, data: &mut [u8]) {
        if !self.has_handshaked() {
            self.handshake();
        }
        let mut c_writer = self.c_conn.writer();
        let mut offset = 0;
        while offset < data.len() {
            offset += c_writer.write(&data[offset..]).unwrap();
        }
        c_writer.flush().unwrap();

        let mut s_writer = self.s_conn.writer();
        let mut offset = 0;
        while offset < data.len() {
            offset += s_writer.write(&data[offset..]).unwrap();
        }

        self.process_conn(Mode::Client);
        self.process_conn(Mode::Server);
        self.process_conn(Mode::Client);
        //self.transfer_and_process();

        let mut c_reader = self.c_conn.reader();
        let mut offset = 0;
        while offset < data.len() {
            offset += c_reader.read(data).unwrap();
        }

        let mut s_reader = self.s_conn.reader();
        let mut offset = 0;
        while offset < data.len() {
            offset += s_reader.read(data).unwrap();
        }
    }
}
