// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    harness::{
        read_to_bytes, CipherSuite, ConnectedBuffer, CryptoConfig, HandshakeType, KXGroup, Mode,
        TlsConnection,
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
    io::{ErrorKind, Read, Write},
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
    mode: Mode,
    config: s2n_tls::config::Config,
    ticket_storage: SessionTicketStorage,
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
            .wipe_trust_store()?
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
            mode,
            config: builder.build()?,
            ticket_storage: session_ticket_storage,
        })
    }
}

pub struct S2NConnection {
    // Pin<Box<T>> is to ensure long-term *mut to IO buffers remains valid
    connected_buffer: Pin<Box<ConnectedBuffer>>,
    connection: Connection,
    handshake_completed: bool,
}

impl S2NConnection {
    /// Unsafe callback for custom IO C API
    ///
    /// s2n-tls IO is usually used with file descriptors to a TCP socket, but we
    /// reduce overhead and outside noise with a local buffer for benchmarking
    unsafe extern "C" fn send_cb(context: *mut c_void, data: *const u8, len: u32) -> c_int {
        let context = &mut *(context as *mut ConnectedBuffer);
        let data = core::slice::from_raw_parts(data, len as _);
        context.write(data).unwrap() as _
    }

    /// Unsafe callback for custom IO C API
    unsafe extern "C" fn recv_cb(context: *mut c_void, data: *mut u8, len: u32) -> c_int {
        let context = &mut *(context as *mut ConnectedBuffer);
        let data = core::slice::from_raw_parts_mut(data, len as _);
        context.flush().unwrap();
        match context.read(data) {
            Err(err) => {
                // s2n-tls requires the callback to set errno if blocking happens
                if let ErrorKind::WouldBlock = err.kind() {
                    errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
                    -1
                } else {
                    panic!("{err:?}");
                }
            }
            Ok(len) => len as _,
        }
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

impl TlsConnection for S2NConnection {
    type Config = S2NConfig;

    fn name() -> String {
        "s2n-tls".to_string()
    }

    fn new_from_config(
        config: &Self::Config,
        connected_buffer: ConnectedBuffer,
    ) -> Result<Self, Box<dyn Error>> {
        let mode = match config.mode {
            Mode::Client => s2n_tls::enums::Mode::Client,
            Mode::Server => s2n_tls::enums::Mode::Server,
        };

        let mut connected_buffer = Box::pin(connected_buffer);

        let mut connection = Connection::new(mode);
        connection
            .set_blinding(Blinding::SelfService)?
            .set_config(config.config.clone())?
            .set_send_callback(Some(Self::send_cb))?
            .set_receive_callback(Some(Self::recv_cb))?;
        unsafe {
            connection
                .set_send_context(&mut *connected_buffer as *mut ConnectedBuffer as *mut c_void)?
                .set_receive_context(
                    &mut *connected_buffer as *mut ConnectedBuffer as *mut c_void,
                )?;
        }

        if let Some(ticket) = config.ticket_storage.0.lock().unwrap().borrow_mut().take() {
            connection.set_session_ticket(&ticket)?;
        }

        Ok(Self {
            connected_buffer,
            connection,
            handshake_completed: false,
        })
    }

    fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        self.handshake_completed = self
            .connection
            .poll_negotiate()
            .map(|res| res.unwrap()) // unwrap `Err` if present
            .is_ready();
        Ok(())
    }

    fn handshake_completed(&self) -> bool {
        self.handshake_completed
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

    fn send(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut write_offset = 0;
        while write_offset < data.len() {
            match self.connection.poll_send(&data[write_offset..]) {
                Poll::Ready(bytes_written) => write_offset += bytes_written?,
                Poll::Pending => return Err("unexpected pending".into()),
            }
            assert!(self.connection.poll_flush().is_ready());
        }
        Ok(())
    }

    fn recv(&mut self, data: &mut [u8]) -> Result<(), Box<dyn Error>> {
        let data_len = data.len();
        let mut read_offset = 0;
        while read_offset < data_len {
            match self.connection.poll_recv(data) {
                Poll::Ready(bytes_read) => read_offset += bytes_read?,
                Poll::Pending => return Err("unexpected pending".into()),
            }
        }
        Ok(())
    }

    fn shrink_connection_buffers(&mut self) {
        self.connection.release_buffers().unwrap();
    }

    fn shrink_connected_buffer(&mut self) {
        self.connected_buffer.shrink();
    }

    fn connected_buffer(&self) -> &ConnectedBuffer {
        &self.connected_buffer
    }
}
