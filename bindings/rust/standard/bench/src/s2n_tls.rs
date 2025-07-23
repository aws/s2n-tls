// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    harness::{
        self, read_to_bytes, CipherSuite, CryptoConfig, HandshakeType, KXGroup, Mode,
        TlsConnection, TlsInfo, ViewIO,
    },
    PemType::*,
};
use s2n_tls::{
    callbacks::{SessionTicketCallback, VerifyHostNameCallback},
    config::Builder,
    connection::Connection,
    enums::{Blinding, ClientAuthType, Version},
    security::Policy,
};
use std::{
    borrow::BorrowMut,
    error::Error,
    ffi::c_void,
    io::ErrorKind,
    os::raw::c_int,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
    time::SystemTime,
};

/// Custom callback for verifying hostnames. Rustls requires checking hostnames,
/// so this is to make a fair comparison
struct HostNameHandler {
    expected_server_name: &'static str,
}
impl VerifyHostNameCallback for HostNameHandler {
    fn verify_host_name(&self, hostname: &str) -> bool {
        self.expected_server_name == hostname
    }
}

/// An s2n send callback for some generic type `T` where `T: Write`.
///
/// # Safety
/// The context must be semantically `Pin`, because it is stored as a raw pointer.
/// The pointer must be one layer of indirection, e.g. `*mut T`.
pub unsafe extern "C" fn generic_send_cb<T: std::io::Write>(
    context: *mut c_void,
    data: *const u8,
    len: u32,
) -> c_int {
    let context: &mut T = &mut *(context as *mut T);
    let data = core::slice::from_raw_parts(data, len as _);
    let bytes_written = context.write(data).unwrap();
    bytes_written as c_int
}

/// An s2n recv callback for some generic type `T` where `T: Read`.
///
/// # Safety
/// The context must be semantically `Pin`, because it is stored as a raw pointer.
/// The pointer must be one layer of indirection, e.g. `*mut T`.
pub unsafe extern "C" fn generic_recv_cb<T: std::io::Read>(
    context: *mut c_void,
    data: *mut u8,
    len: u32,
) -> c_int {
    let context: &mut T = &mut *(context as *mut T);
    let data = core::slice::from_raw_parts_mut(data, len as _);
    match context.read(data) {
        Ok(len) => len as c_int,
        Err(err) if err.kind() == ErrorKind::WouldBlock => {
            errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
            -1
        }
        Err(unrecognized) => panic!("unexpected error: {unrecognized}"),
    }
}

#[derive(Clone, Debug, Default)]
pub struct SessionTicketStorage(Arc<Mutex<Option<Vec<u8>>>>);

impl SessionTicketCallback for SessionTicketStorage {
    fn on_session_ticket(
        &self,
        _connection: &mut s2n_tls::connection::Connection,
        session_ticket: &s2n_tls::callbacks::SessionTicket,
    ) {
        let mut ticket = vec![0; session_ticket.len().unwrap()];
        session_ticket.data(&mut ticket).unwrap();
        let _ = self.0.lock().unwrap().insert(ticket);
    }
}

const KEY_NAME: &str = "InsecureTestKey";
const KEY_VALUE: [u8; 16] = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3];

/// s2n-tls has mode-independent configs, so this struct wraps the config with the mode
pub struct S2NConfig {
    config: s2n_tls::config::Config,
    ticket_storage: SessionTicketStorage,
}

impl From<s2n_tls::config::Config> for S2NConfig {
    fn from(value: s2n_tls::config::Config) -> Self {
        S2NConfig {
            config: value,
            ticket_storage: Default::default(),
        }
    }
}

impl crate::harness::TlsBenchConfig for S2NConfig {
    fn make_config(
        mode: Mode,
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Self, Box<dyn Error>> {
        // these security policies negotiate the given cipher suite and key
        // exchange group as their top choice
        let security_policy = match (crypto_config.cipher_suite, crypto_config.kx_group) {
            (CipherSuite::AES_128_GCM_SHA256, KXGroup::Secp256R1) => "20230317",
            (CipherSuite::AES_256_GCM_SHA384, KXGroup::Secp256R1) => "20190802",
            (CipherSuite::AES_128_GCM_SHA256, KXGroup::X25519) => "20240417",
            (CipherSuite::AES_256_GCM_SHA384, KXGroup::X25519) => "20190801",
        };

        let mut builder = Builder::new();
        builder
            .set_security_policy(&Policy::from_version(security_policy)?)?
            .with_system_certs(false)?
            .set_client_auth_type(match handshake_type {
                HandshakeType::MutualAuth => ClientAuthType::Required,
                _ => ClientAuthType::None, // ServerAuth or resumption handshake
            })?;

        if handshake_type == HandshakeType::Resumption {
            builder.enable_session_tickets(true)?;
        }

        let session_ticket_storage = SessionTicketStorage::default();

        match mode {
            Mode::Client => {
                builder
                    .trust_pem(read_to_bytes(CACert, crypto_config.sig_type).as_slice())?
                    .set_verify_host_callback(HostNameHandler {
                        expected_server_name: "localhost",
                    })?;

                match handshake_type {
                    HandshakeType::MutualAuth => {
                        builder.load_pem(
                            read_to_bytes(ClientCertChain, crypto_config.sig_type).as_slice(),
                            read_to_bytes(ClientKey, crypto_config.sig_type).as_slice(),
                        )?;
                    }
                    HandshakeType::Resumption => {
                        builder.set_session_ticket_callback(session_ticket_storage.clone())?;
                    }
                    // no special configuration
                    HandshakeType::ServerAuth => {}
                }
            }
            Mode::Server => {
                builder.load_pem(
                    read_to_bytes(ServerCertChain, crypto_config.sig_type).as_slice(),
                    read_to_bytes(ServerKey, crypto_config.sig_type).as_slice(),
                )?;

                match handshake_type {
                    HandshakeType::MutualAuth => {
                        builder
                            .trust_pem(read_to_bytes(CACert, crypto_config.sig_type).as_slice())?
                            .set_verify_host_callback(HostNameHandler {
                                expected_server_name: "localhost",
                            })?;
                    }
                    HandshakeType::Resumption => {
                        builder.add_session_ticket_key(
                            KEY_NAME.as_bytes(),
                            KEY_VALUE.as_slice(),
                            // use a time that we are sure is in the past to
                            // make the key immediately available
                            SystemTime::UNIX_EPOCH,
                        )?;
                    }
                    // no special configuration for normal handshake
                    HandshakeType::ServerAuth => {}
                };
            }
        }

        Ok(S2NConfig {
            config: builder.build()?,
            ticket_storage: session_ticket_storage,
        })
    }
}

// We allow dead_code, because otherwise the compiler sees `io` as unused because
// it can't reason through the pointers that were passed into the s2n-tls connection
// io contexts.
#[allow(dead_code)]
pub struct S2NConnection {
    io: Pin<Box<ViewIO>>,
    connection: Connection,
}

impl S2NConnection {
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

impl TlsConnection for S2NConnection {
    type Config = S2NConfig;

    fn new_from_config(
        mode: harness::Mode,
        config: &Self::Config,
        io: &harness::TestPairIO,
    ) -> Result<Self, Box<dyn Error>> {
        let s2n_mode = match mode {
            Mode::Client => s2n_tls::enums::Mode::Client,
            Mode::Server => s2n_tls::enums::Mode::Server,
        };

        let io = match mode {
            Mode::Client => io.client_view(),
            Mode::Server => io.server_view(),
        };

        let mut io = Box::pin(io);

        let mut connection = Connection::new(s2n_mode);
        connection
            .set_blinding(Blinding::SelfService)?
            .set_config(config.config.clone())?
            .set_send_callback(Some(generic_send_cb::<ViewIO>))?
            .set_receive_callback(Some(generic_recv_cb::<ViewIO>))?;
        unsafe {
            let raw_view_io = *(&mut io as *mut Pin<Box<ViewIO>> as *mut *mut ViewIO);
            connection
                .set_send_context(raw_view_io as *mut c_void)?
                .set_receive_context(raw_view_io as *mut c_void)?;
        }

        if let Some(ticket) = config.ticket_storage.0.lock().unwrap().borrow_mut().take() {
            connection.set_session_ticket(&ticket)?;
        }

        Ok(Self { io, connection })
    }

    fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        if let Poll::Ready(res) = self.connection.poll_negotiate() {
            res?;
        }
        Ok(())
    }

    fn handshake_completed(&self) -> bool {
        let complete = self
            .connection
            .handshake_type()
            .unwrap()
            .contains("NEGOTIATED");
        complete
    }

    fn send(&mut self, data: &[u8]) {
        let mut write_offset = 0;
        while write_offset < data.len() {
            match self.connection.poll_send(&data[write_offset..]) {
                Poll::Ready(bytes_written) => write_offset += bytes_written.unwrap(),
                Poll::Pending => panic!("unexpected `Pending` poll"),
            }
            assert!(self.connection.poll_flush().is_ready());
        }
    }

    fn recv(&mut self, data: &mut [u8]) -> std::io::Result<()> {
        let data_len = data.len();
        let mut read_offset = 0;
        while read_offset < data_len {
            match self.connection.poll_recv(data) {
                Poll::Ready(bytes_read) => read_offset += bytes_read?,
                Poll::Pending => {
                    return Err(std::io::Error::new(
                        ErrorKind::WouldBlock,
                        "poll_recv returned pending",
                    ))
                }
            }
        }
        Ok(())
    }
    fn shutdown_send(&mut self) {
        assert!(matches!(
            self.connection.poll_shutdown_send(),
            Poll::Ready(_)
        ));
    }

    fn shutdown_finish(&mut self) -> bool {
        matches!(self.connection.poll_shutdown(), Poll::Ready(_))
    }
}

impl TlsInfo for S2NConnection {
    fn name() -> String {
        "s2n-tls".to_string()
    }

    fn get_negotiated_cipher_suite(&self) -> CipherSuite {
        match self.connection.cipher_suite().unwrap() {
            "TLS_AES_128_GCM_SHA256" => CipherSuite::AES_128_GCM_SHA256,
            "TLS_AES_256_GCM_SHA384" => CipherSuite::AES_256_GCM_SHA384,
            _ => panic!("Unknown cipher suite"),
        }
    }

    fn negotiated_tls13(&self) -> bool {
        self.connection.actual_protocol_version().unwrap() == Version::TLS13
    }

    fn resumed_connection(&self) -> bool {
        !self
            .connection
            .handshake_type()
            .unwrap()
            .contains("FULL_HANDSHAKE")
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utilities;

    use super::*;

    #[test]
    fn sanity_check() {
        test_utilities::sanity_check::<S2NConnection>();
    }

    #[test]
    fn all_handshakes() {
        test_utilities::all_handshakes::<S2NConnection>();
    }

    #[test]
    fn transfer() {
        test_utilities::transfer::<S2NConnection>();
    }
}
