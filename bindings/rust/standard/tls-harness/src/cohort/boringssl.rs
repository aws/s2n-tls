// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    PemType, get_cert_path,
    harness::{self, Mode, TlsConfigBuilder, TlsConnection, TlsInfo, ViewIO},
};
use boring::ssl::{
    ErrorCode, ShutdownResult, Ssl, SslContext, SslContextBuilder, SslFiletype, SslMethod,
    SslSession, SslStream, SslVersion,
};
use std::{
    error::Error,
    io::{Read, Write},
    rc::Rc,
    sync::{Arc, Mutex},
};

// Creates session ticket callback handler
#[derive(Clone, Default)]
pub struct SessionTicketStorage {
    pub stored_ticket: Arc<Mutex<Option<SslSession>>>,
}

pub struct BoringSslConnection {
    mode: Mode,
    connection: SslStream<ViewIO>,
}

pub struct BoringSslConfig {
    pub config: SslContext,
    pub session_ticket_storage: SessionTicketStorage,
}

impl From<SslContext> for BoringSslConfig {
    fn from(ctx: SslContext) -> Self {
        BoringSslConfig {
            config: ctx,
            session_ticket_storage: Default::default(),
        }
    }
}

impl TlsConnection for BoringSslConnection {
    type Config = BoringSslConfig;

    fn new_from_config(
        mode: harness::Mode,
        config: &Self::Config,
        io: &Rc<harness::TestPairIO>,
    ) -> Result<Self, Box<dyn Error>> {
        // Check if there is a session ticket available.
        // A session ticket will only be available if the Config was created
        // with session resumption enabled (and a previous handshake stored it).
        let maybe_ticket = config
            .session_ticket_storage
            .stored_ticket
            .lock()
            .unwrap()
            .take();

        // Populate the internal session cache (mirrors the OpenSSL harness pattern).
        if let Some(ticket) = &maybe_ticket {
            let _ = unsafe { config.config.add_session(ticket) };
        }

        let mut ssl = Ssl::new(&config.config)?;

        // If we have a ticket, attempt to resume with it.
        if let Some(ticket) = &maybe_ticket {
            unsafe { ssl.set_session(ticket)? };
        }

        let view = match mode {
            Mode::Client => io.client_view(),
            Mode::Server => io.server_view(),
        };

        let stream = SslStream::new(ssl, view)?;
        Ok(Self {
            mode,
            connection: stream,
        })
    }

    fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        // If the handshake is already complete, no further work is needed.
        if self.connection.ssl().is_init_finished() {
            return Ok(());
        }

        // Drive handshake based on configured mode.
        let result = match self.mode {
            Mode::Server => self.connection.accept(),
            Mode::Client => self.connection.connect(),
        };

        match result {
            // Completed a handshake step — not necessarily “done” yet.
            Ok(_) => Ok(()),

            // Nonblocking WANT_READ / WANT_WRITE are normal while handshaking.
            Err(err) => match err.code() {
                ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => Ok(()),
                _ => Err(err.into()),
            },
        }
    }

    fn handshake_completed(&self) -> bool {
        self.connection.ssl().is_init_finished()
    }

    fn send(&mut self, data: &[u8]) {
        let mut write_offset = 0;
        while write_offset < data.len() {
            write_offset += self.connection.write(&data[write_offset..]).unwrap();
            self.connection.flush().unwrap(); // make sure internal buffers don't fill up
        }
    }

    fn recv(&mut self, data: &mut [u8]) -> std::io::Result<()> {
        let data_len = data.len();
        let mut read_offset = 0;
        while read_offset < data_len {
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

impl TlsInfo for BoringSslConnection {
    fn name() -> String {
        "boringssl".to_string()
    }

    fn get_negotiated_cipher_suite(&self) -> String {
        self.connection
            .ssl()
            .current_cipher()
            .expect("Handshake not completed")
            .name()
            .to_string()
    }

    fn negotiated_tls13(&self) -> bool {
        self.connection
            .ssl()
            .version2()
            .expect("Handshake not completed")
            == SslVersion::TLS1_3
    }

    fn resumed_connection(&self) -> bool {
        self.connection.ssl().session_reused()
    }

    fn mutual_auth(&self) -> bool {
        assert!(self.connection.ssl().is_server());
        self.connection.ssl().peer_certificate().is_some()
            && self.connection.ssl().verify_result().is_ok()
    }
}

impl TlsConfigBuilder for SslContextBuilder {
    type Config = BoringSslConfig;

    fn new_test_config(mode: Mode) -> Self {
        match mode {
            Mode::Client => SslContext::builder(SslMethod::tls_client()).unwrap(),
            Mode::Server => SslContext::builder(SslMethod::tls_server()).unwrap(),
        }
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
        BoringSslConfig {
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
        test_utilities::handshake::<BoringSslConnection, SslContextBuilder>();
    }

    #[test]
    fn transfer() {
        test_utilities::transfer::<BoringSslConnection, SslContextBuilder>();
    }
}
