// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    harness::{
        read_to_bytes, CipherSuite, ConnectedBuffer, CryptoConfig, HandshakeType, KXGroup, Mode,
        TlsBenchConfig, TlsConnection,
    },
    PemType::{self, *},
    SigType,
};
use rustls::{
    crypto::{
        aws_lc_rs::{
            self,
            cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384},
            kx_group::{SECP256R1, X25519},
        },
        CryptoProvider,
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    server::WebPkiClientVerifier,
    version::TLS13,
    ClientConfig, ClientConnection, Connection,
    ProtocolVersion::TLSv1_3,
    RootCertStore, ServerConfig, ServerConnection,
};
use std::{
    error::Error,
    io::{BufReader, Read, Write},
    sync::Arc,
};

pub struct RustlsConnection {
    connected_buffer: ConnectedBuffer,
    connection: Connection,
}

impl RustlsConnection {
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Treat `WouldBlock` as an `Ok` value for when blocking is expected
    fn ignore_block<T: Default>(res: Result<T, std::io::Error>) -> Result<T, std::io::Error> {
        match res {
            Ok(t) => Ok(t),
            Err(err) => match err.kind() {
                std::io::ErrorKind::WouldBlock => Ok(T::default()),
                _ => Err(err),
            },
        }
    }
}

impl RustlsConfig {
    fn get_root_cert_store(sig_type: SigType) -> RootCertStore {
        let mut root_store = RootCertStore::empty();
        root_store.add_parsable_certificates(
            rustls_pemfile::certs(&mut BufReader::new(&*read_to_bytes(CACert, sig_type)))
                .map(|r| r.unwrap()),
        );
        root_store
    }

    fn get_cert_chain(pem_type: PemType, sig_type: SigType) -> Vec<CertificateDer<'static>> {
        rustls_pemfile::certs(&mut BufReader::new(&*read_to_bytes(pem_type, sig_type)))
            .map(|result| result.unwrap())
            .collect()
    }

    fn get_key(pem_type: PemType, sig_type: SigType) -> PrivateKeyDer<'static> {
        let key =
            rustls_pemfile::read_one(&mut BufReader::new(&*read_to_bytes(pem_type, sig_type)))
                .unwrap();
        if let Some(rustls_pemfile::Item::Pkcs8Key(pkcs_8_key)) = key {
            return pkcs_8_key.into();
        } else {
            // https://docs.rs/rustls-pemfile/latest/rustls_pemfile/enum.Item.html
            panic!("unexpected key type: {:?}", key);
        }
    }
}

/// Clients and servers have different config types in Rustls, so wrap them in an enum
pub enum RustlsConfig {
    Client(Arc<ClientConfig>),
    Server(Arc<ServerConfig>),
}

impl TlsBenchConfig for RustlsConfig {
    fn make_config(
        mode: Mode,
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Self, Box<dyn Error>> {
        let cipher_suite = match crypto_config.cipher_suite {
            CipherSuite::AES_128_GCM_SHA256 => TLS13_AES_128_GCM_SHA256,
            CipherSuite::AES_256_GCM_SHA384 => TLS13_AES_256_GCM_SHA384,
        };

        let kx_group = match crypto_config.kx_group {
            KXGroup::Secp256R1 => &SECP256R1,
            KXGroup::X25519 => &X25519,
        };

        let crypto_provider = Arc::new(CryptoProvider {
            cipher_suites: vec![cipher_suite],
            kx_groups: vec![*kx_group],
            ..aws_lc_rs::default_provider()
        });

        match mode {
            Mode::Client => {
                let builder = ClientConfig::builder_with_provider(crypto_provider)
                    .with_protocol_versions(&[&TLS13])?
                    .with_root_certificates(Self::get_root_cert_store(crypto_config.sig_type));

                let config = match handshake_type {
                    HandshakeType::ServerAuth | HandshakeType::Resumption => {
                        builder.with_no_client_auth()
                    }
                    HandshakeType::MutualAuth => builder.with_client_auth_cert(
                        Self::get_cert_chain(ClientCertChain, crypto_config.sig_type),
                        Self::get_key(ClientKey, crypto_config.sig_type),
                    )?,
                };

                if handshake_type != HandshakeType::Resumption {
                    rustls::client::Resumption::disabled();
                }

                Ok(RustlsConfig::Client(Arc::new(config)))
            }
            Mode::Server => {
                let builder = ServerConfig::builder_with_provider(crypto_provider)
                    .with_protocol_versions(&[&TLS13])?;

                let builder = match handshake_type {
                    HandshakeType::ServerAuth | HandshakeType::Resumption => {
                        builder.with_no_client_auth()
                    }
                    HandshakeType::MutualAuth => {
                        let client_cert_verifier = WebPkiClientVerifier::builder(
                            Self::get_root_cert_store(crypto_config.sig_type).into(),
                        )
                        .build()
                        .unwrap();
                        builder.with_client_cert_verifier(client_cert_verifier)
                    }
                };

                let config = builder.with_single_cert(
                    Self::get_cert_chain(ServerCertChain, crypto_config.sig_type),
                    Self::get_key(ServerKey, crypto_config.sig_type),
                )?;

                Ok(RustlsConfig::Server(Arc::new(config)))
            }
        }
    }
}

impl TlsConnection for RustlsConnection {
    type Config = RustlsConfig;

    fn name() -> String {
        "rustls".to_string()
    }

    fn new_from_config(
        config: &Self::Config,
        connected_buffer: ConnectedBuffer,
    ) -> Result<Self, Box<dyn Error>> {
        let connection = match config {
            RustlsConfig::Client(config) => Connection::Client(ClientConnection::new(
                config.clone(),
                ServerName::try_from("localhost")?,
            )?),
            RustlsConfig::Server(config) => {
                Connection::Server(ServerConnection::new(config.clone())?)
            }
        };

        Ok(Self {
            connected_buffer,
            connection,
        })
    }

    fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        Self::ignore_block(self.connection.complete_io(&mut self.connected_buffer))?;
        Ok(())
    }

    fn handshake_completed(&self) -> bool {
        !self.connection.is_handshaking()
    }

    fn get_negotiated_cipher_suite(&self) -> CipherSuite {
        match self.connection.negotiated_cipher_suite().unwrap().suite() {
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => CipherSuite::AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => CipherSuite::AES_256_GCM_SHA384,
            _ => panic!("Unknown cipher suite"),
        }
    }

    fn negotiated_tls13(&self) -> bool {
        self.connection
            .protocol_version()
            .expect("Handshake not completed")
            == TLSv1_3
    }

    fn send(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut write_offset = 0;
        while write_offset < data.len() {
            write_offset += self
                .connection
                .writer()
                .write(&data[write_offset..data.len()])?;
            self.connection.writer().flush()?;
            self.connection.complete_io(&mut self.connected_buffer)?;
        }
        Ok(())
    }

    fn recv(&mut self, data: &mut [u8]) -> Result<(), Box<dyn Error>> {
        let data_len = data.len();
        let mut read_offset = 0;
        while read_offset < data.len() {
            self.connection.complete_io(&mut self.connected_buffer)?;
            read_offset += Self::ignore_block(
                self.connection
                    .reader()
                    .read(&mut data[read_offset..data_len]),
            )?;
        }
        Ok(())
    }

    fn shrink_connection_buffers(&mut self) {
        self.connection.set_buffer_limit(Some(1));
    }

    fn shrink_connected_buffer(&mut self) {
        self.connected_buffer.shrink();
    }

    fn connected_buffer(&self) -> &ConnectedBuffer {
        &self.connected_buffer
    }

    fn resumed_connection(&self) -> bool {
        if let rustls::Connection::Server(s) = &self.connection {
            s.received_resumption_data().is_some()
        } else {
            panic!("rustls connection resumption status must be check on the server side");
        }
    }
}
