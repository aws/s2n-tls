// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    get_cert_path,
    harness::{self, Mode, TlsConfigBuilder, TlsConnection, TlsInfo, ViewIO},
    PemType,
};
use openssl::ssl::{
    ErrorCode, ShutdownResult, Ssl, SslContext, SslContextBuilder, SslFiletype, SslMethod,
    SslSession, SslStream, SslVersion,
};
use std::{
    error::Error,
    io::{Read, Write},
    sync::{Arc, Mutex},
};

// Creates session ticket callback handler
#[derive(Clone, Default)]
pub struct SessionTicketStorage {
    pub stored_ticket: Arc<Mutex<Option<SslSession>>>,
}

pub struct OpenSslConnection {
    connection: SslStream<ViewIO>,
}

pub struct OpenSslConfig {
    pub config: SslContext,
    pub session_ticket_storage: SessionTicketStorage,
}

impl From<SslContext> for OpenSslConfig {
    fn from(value: SslContext) -> Self {
        OpenSslConfig {
            config: value,
            session_ticket_storage: Default::default(),
        }
    }
}

impl TlsConnection for OpenSslConnection {
    type Config = OpenSslConfig;

    fn new_from_config(
        mode: harness::Mode,
        config: &Self::Config,
        io: &harness::TestPairIO,
    ) -> Result<Self, Box<dyn Error>> {
        // check if there is a session ticket available
        // a session ticket will only be available if the Config was created
        // with session resumption enabled
        let maybe_ticket = config
            .session_ticket_storage
            .stored_ticket
            .lock()
            .unwrap()
            .take();
        if let Some(ticket) = &maybe_ticket {
            let _result = unsafe { config.config.add_session(ticket) };
        }

        let mut connection = Ssl::new(&config.config)?;
        if let Some(ticket) = &maybe_ticket {
            unsafe { connection.set_session(ticket)? };
        }

        let io = match mode {
            Mode::Client => io.client_view(),
            Mode::Server => io.server_view(),
        };

        let connection = SslStream::new(connection, io)?;
        Ok(Self { connection })
    }

    fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        let result = if self.connection.ssl().is_server() {
            self.connection.accept()
        } else {
            self.connection.connect()
        };

        // treat blocking (`ErrorCode::WANT_READ`) as `Ok`, expected during handshake
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

    fn handshake_completed(&self) -> bool {
        self.connection.ssl().is_init_finished()
    }

    fn send(&mut self, data: &[u8]) {
        let mut write_offset = 0;
        while write_offset < data.len() {
            write_offset += self
                .connection
                .write(&data[write_offset..data.len()])
                .unwrap();
            self.connection.flush().unwrap(); // make sure internal buffers don't fill up
        }
    }

    fn recv(&mut self, data: &mut [u8]) -> std::io::Result<()> {
        let data_len = data.len();
        let mut read_offset = 0;
        while read_offset < data.len() {
            read_offset += self.connection.read(&mut data[read_offset..data_len])?
        }
        Ok(())
    }

    fn shutdown_send(&mut self) {
        // this method will not read in a CloseNotify
        assert_eq!(self.connection.shutdown().unwrap(), ShutdownResult::Sent);
    }

    fn shutdown_finish(&mut self) -> bool {
        self.connection.shutdown().unwrap() == ShutdownResult::Received
    }
}

impl TlsInfo for OpenSslConnection {
    fn name() -> String {
        let version_num = openssl::version::number() as u64;
        let patch: u8 = (version_num >> 4) as u8;
        let fix = (version_num >> 12) as u8;
        let minor = (version_num >> 20) as u8;
        let major = (version_num >> 28) as u8;
        format!(
            "openssl{}.{}.{}{}",
            major,
            minor,
            fix,
            (b'a' + patch - 1) as char
        )
    }

    fn get_negotiated_cipher_suite(&self) -> String {
        let cipher_suite = self
            .connection
            .ssl()
            .current_cipher()
            .expect("Handshake not completed")
            .name();
        cipher_suite.to_string()
    }

    fn negotiated_tls13(&self) -> bool {
        self.connection
            .ssl()
            .version2() // version() -> &str is deprecated, version2() returns an enum instead
            .expect("Handshake not completed")
            == SslVersion::TLS1_3
    }

    fn resumed_connection(&self) -> bool {
        self.connection.ssl().session_reused()
    }

    fn mutual_auth(&self) -> bool {
        assert!(self.connection.ssl().is_server());
        self.connection.ssl().verified_chain().is_some()
    }
}

impl TlsConfigBuilder for SslContextBuilder {
    type Config = OpenSslConfig;

    fn new_test_config(mode: Mode) -> Self {
        let mut builder = match mode {
            Mode::Client => SslContext::builder(SslMethod::tls_client()).unwrap(),
            Mode::Server => SslContext::builder(SslMethod::tls_server()).unwrap(),
        };
        builder.set_security_level(0);
        builder
    }

    fn set_chain(&mut self, sig_type: crate::SigType) {
        self.set_certificate_chain_file(get_cert_path(PemType::ServerCertChain, sig_type))
            .unwrap();
        self.set_private_key_file(
            get_cert_path(PemType::ServerKey, sig_type),
            SslFiletype::PEM,
        )
        .unwrap();
    }

    fn set_trust(&mut self, sig_type: crate::SigType) {
        self.set_ca_file(get_cert_path(PemType::CACert, sig_type))
            .unwrap();
    }

    fn build(self) -> Self::Config {
        OpenSslConfig {
            config: self.build(),
            session_ticket_storage: SessionTicketStorage::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utilities;

    use super::*;

    #[test]
    fn handshake() {
        test_utilities::handshake::<OpenSslConnection, SslContextBuilder>();
    }

    #[test]
    fn transfer() {
        test_utilities::transfer::<OpenSslConnection, SslContextBuilder>();
    }
}
