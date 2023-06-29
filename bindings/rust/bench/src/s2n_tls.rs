// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    harness::{
        read_to_bytes, CipherSuite, ConnectedBuffer, CryptoConfig, ECGroup, Mode, TlsBenchHarness,
    },
    CA_CERT_PATH, SERVER_CERT_CHAIN_PATH, SERVER_KEY_PATH,
};
use s2n_tls::{
    callbacks::VerifyHostNameCallback,
    config::{Builder, Config},
    connection::Connection,
    enums::{Blinding, Version},
    security::Policy,
};
use std::{
    error::Error,
    ffi::c_void,
    io::{ErrorKind, Read, Write},
    os::raw::c_int,
    pin::Pin,
    task::Poll::Ready,
};

pub struct S2NHarness {
    // UnsafeCell is needed b/c client and server share *mut to IO buffers
    // Pin<Box<T>> is to ensure long-term *mut to IO buffers remain valid
    _client_buf: Pin<Box<ConnectedBuffer>>,
    _server_buf: Pin<Box<ConnectedBuffer>>,
    client_conn: Connection,
    server_conn: Connection,
    client_handshake_completed: bool,
    server_handshake_completed: bool,
}

/// Custom callback for verifying hostnames. Rustls requires checking hostnames,
/// so this is to make a fair comparison
struct HostNameHandler<'a> {
    expected_server_name: &'a str,
}
impl VerifyHostNameCallback for HostNameHandler<'_> {
    fn verify_host_name(&self, hostname: &str) -> bool {
        self.expected_server_name == hostname
    }
}

impl S2NHarness {
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

    fn create_config(mode: Mode, crypto_config: &CryptoConfig) -> Result<Config, Box<dyn Error>> {
        let security_policy = match (&crypto_config.cipher_suite, &crypto_config.ec_group) {
            (CipherSuite::AES_128_GCM_SHA256, ECGroup::SECP256R1) => "20230317",
            (CipherSuite::AES_256_GCM_SHA384, ECGroup::SECP256R1) => "20190802",
            (CipherSuite::AES_128_GCM_SHA256, ECGroup::X25519) => "default_tls13",
            (CipherSuite::AES_256_GCM_SHA384, ECGroup::X25519) => "20190801",
        };

        let mut builder = Builder::new();
        builder.set_security_policy(&Policy::from_version(security_policy)?)?;

        match mode {
            Mode::Server => builder.load_pem(
                read_to_bytes(SERVER_CERT_CHAIN_PATH).as_slice(),
                read_to_bytes(SERVER_KEY_PATH).as_slice(),
            )?,
            Mode::Client => builder
                .trust_pem(read_to_bytes(CA_CERT_PATH).as_slice())?
                .set_verify_host_callback(HostNameHandler {
                    expected_server_name: "localhost",
                })?,
        };

        Ok(builder.build()?)
    }

    /// Set up connections with config and custom IO
    fn init_conn(
        conn: &mut Connection,
        buffer: &mut Pin<Box<ConnectedBuffer>>,
        config: Config,
    ) -> Result<(), Box<dyn Error>> {
        conn.set_blinding(Blinding::SelfService)?
            .set_config(config)?
            .set_send_callback(Some(Self::send_cb))?
            .set_receive_callback(Some(Self::recv_cb))?;
        unsafe {
            conn.set_send_context(&mut **buffer as *mut ConnectedBuffer as *mut c_void)?
                .set_receive_context(&mut **buffer as *mut ConnectedBuffer as *mut c_void)?;
        }

        Ok(())
    }

    /// Handshake step for one connection
    fn handshake_conn(&mut self, mode: Mode) -> Result<(), Box<dyn Error>> {
        let (conn, handshake_completed) = match mode {
            Mode::Client => (&mut self.client_conn, &mut self.client_handshake_completed),
            Mode::Server => (&mut self.server_conn, &mut self.server_handshake_completed),
        };

        if let Ready(res) = conn.poll_negotiate() {
            res?;
            *handshake_completed = true;
        } else {
            *handshake_completed = false;
        }
        Ok(())
    }
}

impl TlsBenchHarness for S2NHarness {
    fn new(crypto_config: &CryptoConfig, buffer: ConnectedBuffer) -> Result<Self, Box<dyn Error>> {
        let mut client_buf = Box::pin(buffer);
        let mut server_buf = Box::pin(client_buf.clone_inverse());

        let client_config = Self::create_config(Mode::Client, crypto_config)?;
        let server_config = Self::create_config(Mode::Server, crypto_config)?;

        let mut client_conn = Connection::new_client();
        let mut server_conn = Connection::new_server();

        Self::init_conn(&mut client_conn, &mut client_buf, client_config)?;
        Self::init_conn(&mut server_conn, &mut server_buf, server_config)?;

        let harness = Self {
            _client_buf: client_buf,
            _server_buf: server_buf,
            client_conn,
            server_conn,
            client_handshake_completed: false,
            server_handshake_completed: false,
        };

        Ok(harness)
    }

    fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        for _ in 0..2 {
            self.handshake_conn(Mode::Client)?;
            self.handshake_conn(Mode::Server)?;
        }
        Ok(())
    }

    fn handshake_completed(&self) -> bool {
        self.client_handshake_completed && self.server_handshake_completed
    }

    fn get_negotiated_cipher_suite(&self) -> CipherSuite {
        match self.client_conn.cipher_suite().unwrap() {
            "TLS_AES_128_GCM_SHA256" => CipherSuite::AES_128_GCM_SHA256,
            "TLS_AES_256_GCM_SHA384" => CipherSuite::AES_256_GCM_SHA384,
            _ => panic!("Unknown cipher suite"),
        }
    }

    fn negotiated_tls13(&self) -> bool {
        self.client_conn.actual_protocol_version().unwrap() == Version::TLS13
    }
}
