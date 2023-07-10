// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    harness::{
        CipherSuite, ConnectedBuffer, CryptoConfig, ECGroup, HandshakeType, Mode, TlsBenchHarness,
    },
    CA_CERT_PATH, CLIENT_CERT_CHAIN_PATH, CLIENT_KEY_PATH, SERVER_CERT_CHAIN_PATH, SERVER_KEY_PATH,
};
use openssl::ssl::{
    ErrorCode, Ssl, SslContext, SslContextBuilder, SslFiletype, SslMethod, SslStream,
    SslVerifyMode, SslVersion,
};
use std::{
    error::Error,
    io::{Read, Write},
};

pub struct OpenSslHarness {
    client_conn: SslStream<ConnectedBuffer>,
    server_conn: SslStream<ConnectedBuffer>,
}

impl OpenSslHarness {
    fn common_config(
        builder: &mut SslContextBuilder,
        cipher_suite: &str,
        ec_key: &str,
    ) -> Result<(), Box<dyn Error>> {
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_ciphersuites(cipher_suite)?;
        builder.set_groups_list(ec_key)?;
        Ok(())
    }
    /// Process handshake for one connection, treating blocking errors as `Ok`
    fn handshake_conn(&mut self, mode: Mode) -> Result<(), Box<dyn Error>> {
        let result = match mode {
            Mode::Client => self.client_conn.connect(),
            Mode::Server => self.server_conn.accept(),
        };
        match result {
            Ok(_) => Ok(()),
            Err(err) => {
                if err.code() != ErrorCode::WANT_READ {
                    Err(err.into())
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl TlsBenchHarness for OpenSslHarness {
    fn new(
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Self, Box<dyn Error>> {
        let client_buf = ConnectedBuffer::new();
        let server_buf = client_buf.clone_inverse();

        let cipher_suite = match crypto_config.cipher_suite {
            CipherSuite::AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
            CipherSuite::AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
        };

        let ec_key = match crypto_config.ec_group {
            ECGroup::SECP256R1 => "P-256",
            ECGroup::X25519 => "X25519",
        };

        let mut client_builder = SslContext::builder(SslMethod::tls_client())?;
        client_builder.set_ca_file(CA_CERT_PATH)?;
        Self::common_config(&mut client_builder, cipher_suite, ec_key)?;

        let mut server_builder = SslContext::builder(SslMethod::tls_server())?;
        server_builder.set_certificate_chain_file(SERVER_CERT_CHAIN_PATH)?;
        server_builder.set_private_key_file(SERVER_KEY_PATH, SslFiletype::PEM)?;
        Self::common_config(&mut server_builder, cipher_suite, ec_key)?;

        if handshake_type == HandshakeType::MutualAuth {
            client_builder.set_certificate_chain_file(CLIENT_CERT_CHAIN_PATH)?;
            client_builder.set_private_key_file(CLIENT_KEY_PATH, SslFiletype::PEM)?;
            server_builder.set_ca_file(CA_CERT_PATH)?;
            server_builder.set_verify(SslVerifyMode::FAIL_IF_NO_PEER_CERT | SslVerifyMode::PEER);
        }

        let client_config = client_builder.build();
        let server_config = server_builder.build();

        let client_conn = SslStream::new(Ssl::new(&client_config)?, client_buf)?;
        let server_conn = SslStream::new(Ssl::new(&server_config)?, server_buf)?;

        Ok(Self {
            client_conn,
            server_conn,
        })
    }

    fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        for _ in 0..2 {
            self.handshake_conn(Mode::Client)?;
            self.handshake_conn(Mode::Server)?;
        }
        Ok(())
    }

    fn handshake_completed(&self) -> bool {
        self.client_conn.ssl().is_init_finished() && self.server_conn.ssl().is_init_finished()
    }

    fn get_negotiated_cipher_suite(&self) -> CipherSuite {
        let cipher_suite = self
            .client_conn
            .ssl()
            .current_cipher()
            .expect("Handshake not completed")
            .name();
        match cipher_suite {
            "TLS_AES_128_GCM_SHA256" => CipherSuite::AES_128_GCM_SHA256,
            "TLS_AES_256_GCM_SHA384" => CipherSuite::AES_256_GCM_SHA384,
            _ => panic!("Unknown cipher suite"),
        }
    }

    fn negotiated_tls13(&self) -> bool {
        self.client_conn
            .ssl()
            .version2() // version() -> &str is deprecated, version2() returns an enum instead
            .expect("Handshake not completed")
            == SslVersion::TLS1_3
    }

    fn send(&mut self, sender: Mode, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let send_conn = match sender {
            Mode::Client => &mut self.client_conn,
            Mode::Server => &mut self.server_conn,
        };

        let mut write_offset = 0;
        while write_offset < data.len() {
            write_offset += send_conn.write(&data[write_offset..data.len()])?;
            send_conn.flush()?; // make sure internal buffers don't fill up
        }

        Ok(())
    }

    fn recv(&mut self, receiver: Mode, data: &mut [u8]) -> Result<(), Box<dyn Error>> {
        let recv_conn = match receiver {
            Mode::Client => &mut self.client_conn,
            Mode::Server => &mut self.server_conn,
        };

        let mut read_offset = 0;
        while read_offset < data.len() {
            read_offset += recv_conn.read(data)?
        }

        Ok(())
    }
}
