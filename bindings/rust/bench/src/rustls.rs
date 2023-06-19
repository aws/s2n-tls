// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    harness::{
        read_to_bytes, CipherSuite, ConnectedBuffer, CryptoConfig, ECGroup, Mode, TlsBenchHarness,
    },
    CA_CERT_PATH, SERVER_CERT_CHAIN_PATH, SERVER_KEY_PATH,
};
use rustls::{
    cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384},
    kx_group::{SECP256R1, X25519},
    version::TLS13,
    Certificate, ClientConfig, ClientConnection, PrivateKey,
    ProtocolVersion::TLSv1_3,
    RootCertStore, ServerConfig, ServerConnection, ServerName,
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{error::Error, io::BufReader, sync::Arc};

pub struct RustlsHarness {
    client_buf: ConnectedBuffer,
    server_buf: ConnectedBuffer,
    client_conn: ClientConnection,
    server_conn: ServerConnection,
}

impl RustlsHarness {
    fn get_root_cert_store() -> Result<RootCertStore, Box<dyn Error>> {
        let root_cert =
            Certificate(certs(&mut BufReader::new(&*read_to_bytes(CA_CERT_PATH)))?.remove(0));
        let mut root_certs = RootCertStore::empty();
        root_certs.add(&root_cert)?;
        Ok(root_certs)
    }

    fn get_cert_chain() -> Result<Vec<Certificate>, Box<dyn Error>> {
        let chain = certs(&mut BufReader::new(&*read_to_bytes(SERVER_CERT_CHAIN_PATH)))?;
        Ok(chain
            .iter()
            .map(|bytes| Certificate(bytes.to_vec()))
            .collect())
    }

    fn get_server_key() -> Result<PrivateKey, Box<dyn Error>> {
        Ok(PrivateKey(
            pkcs8_private_keys(&mut BufReader::new(&*read_to_bytes(SERVER_KEY_PATH)))?.remove(0),
        ))
    }

    /// Read all incoming data, process it, and write it out
    /// Works for handshaking and data transfer
    fn process_conn(&mut self, mode: Mode) -> Result<(), std::io::Error> {
        match match mode {
            Mode::Client => self.client_conn.complete_io(&mut self.client_buf),
            Mode::Server => self.server_conn.complete_io(&mut self.server_buf),
        } {
            Ok(_) => Ok(()),
            Err(err) => {
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    Ok(())
                } else {
                    Err(err)
                }
            }
        }
    }
}

impl TlsBenchHarness for RustlsHarness {
    fn new(crypto_config: &CryptoConfig) -> Result<Self, Box<dyn Error>> {
        let client_buf = ConnectedBuffer::new();
        let server_buf = client_buf.clone_inverse();

        let cipher_suite = match crypto_config.cipher_suite {
            CipherSuite::AES_128_GCM_SHA256 => TLS13_AES_128_GCM_SHA256,
            CipherSuite::AES_256_GCM_SHA384 => TLS13_AES_256_GCM_SHA384,
        };

        let kx_group = match crypto_config.ec_group {
            ECGroup::SECP256R1 => &SECP256R1,
            ECGroup::X25519 => &X25519,
        };

        let client_config = Arc::new(
            ClientConfig::builder()
                .with_cipher_suites(&[cipher_suite])
                .with_kx_groups(&[kx_group])
                .with_protocol_versions(&[&TLS13])?
                .with_root_certificates(Self::get_root_cert_store()?)
                .with_no_client_auth(),
        );

        let server_config = Arc::new(
            ServerConfig::builder()
                .with_cipher_suites(&[cipher_suite])
                .with_kx_groups(&[kx_group])
                .with_protocol_versions(&[&TLS13])?
                .with_no_client_auth()
                .with_single_cert(Self::get_cert_chain()?, Self::get_server_key()?)?,
        );

        let client_conn = ClientConnection::new(client_config, ServerName::try_from("localhost")?)?;
        let server_conn = ServerConnection::new(server_config)?;

        Ok(Self {
            client_buf,
            server_buf,
            client_conn,
            server_conn,
        })
    }

    fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        for _ in 0..2 {
            self.process_conn(Mode::Client)?;
            self.process_conn(Mode::Server)?;
        }
        Ok(())
    }

    fn handshake_completed(&self) -> bool {
        !self.client_conn.is_handshaking() && !self.server_conn.is_handshaking()
    }

    fn get_negotiated_cipher_suite(&self) -> CipherSuite {
        match self.client_conn.negotiated_cipher_suite().unwrap().suite() {
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => CipherSuite::AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => CipherSuite::AES_256_GCM_SHA384,
            _ => panic!("Unknown cipher suite"),
        }
    }

    fn negotiated_tls13(&self) -> bool {
        self.client_conn
            .protocol_version()
            .expect("Handshake not completed")
            == TLSv1_3
    }
}
