// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    harness::{
        read_to_bytes, CipherSuite, CryptoConfig, ECGroup, HandshakeType, Mode, TlsBenchHarness,
    },
    CA_CERT_PATH, CLIENT_CERT_CHAIN_PATH, CLIENT_KEY_PATH, SERVER_CERT_CHAIN_PATH, SERVER_KEY_PATH,
};
use s2n_tls::{
    callbacks::VerifyHostNameCallback,
    config::{Builder, Config},
    connection::Connection,
    enums::{Blinding, ClientAuthType, Version},
    security::Policy,
};
use std::{
    cell::UnsafeCell,
    collections::VecDeque,
    error::Error,
    ffi::c_void,
    io::{Read, Write},
    os::raw::c_int,
    pin::Pin,
    task::Poll::Ready,
};

pub struct S2NHarness {
    // UnsafeCell is needed b/c client and server share *mut to IO buffers
    // Pin<Box<T>> is to ensure long-term *mut to IO buffers remain valid
    client_to_server_buf: Pin<Box<UnsafeCell<VecDeque<u8>>>>,
    server_to_client_buf: Pin<Box<UnsafeCell<VecDeque<u8>>>>,
    client_config: Config,
    server_config: Config,
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
        let context = &mut *(context as *mut VecDeque<u8>);
        let data = core::slice::from_raw_parts(data, len as _);
        context.write(data).unwrap() as _
    }

    /// Unsafe callback for custom IO C API
    unsafe extern "C" fn recv_cb(context: *mut c_void, data: *mut u8, len: u32) -> c_int {
        let context = &mut *(context as *mut VecDeque<u8>);
        let data = core::slice::from_raw_parts_mut(data, len as _);
        context.flush().unwrap();
        let len = context.read(data).unwrap();
        if len == 0 {
            errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
            -1
        } else {
            len as _
        }
    }

    fn create_common_config_builder(
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Builder, Box<dyn Error>> {
        let security_policy = match (crypto_config.cipher_suite, crypto_config.ec_group) {
            (CipherSuite::AES_128_GCM_SHA256, ECGroup::SECP256R1) => "20230317",
            (CipherSuite::AES_256_GCM_SHA384, ECGroup::SECP256R1) => "20190802",
            (CipherSuite::AES_128_GCM_SHA256, ECGroup::X25519) => "default_tls13",
            (CipherSuite::AES_256_GCM_SHA384, ECGroup::X25519) => "20190801",
        };

        let mut builder = Builder::new();
        builder
            .set_security_policy(&Policy::from_version(security_policy)?)?
            .wipe_trust_store()?
            .set_client_auth_type(match handshake_type {
                HandshakeType::ServerAuth => ClientAuthType::None,
                HandshakeType::MutualAuth => ClientAuthType::Required,
            })?;

        Ok(builder)
    }

    fn create_client_config(
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Config, Box<dyn Error>> {
        let mut builder = Self::create_common_config_builder(crypto_config, handshake_type)?;
        builder
            .trust_pem(read_to_bytes(CA_CERT_PATH).as_slice())?
            .set_verify_host_callback(HostNameHandler {
                expected_server_name: "localhost",
            })?;

        if handshake_type == HandshakeType::MutualAuth {
            builder.load_pem(
                read_to_bytes(CLIENT_CERT_CHAIN_PATH).as_slice(),
                read_to_bytes(CLIENT_KEY_PATH).as_slice(),
            )?;
        }

        Ok(builder.build()?)
    }

    fn create_server_config(
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Config, Box<dyn Error>> {
        let mut builder = Self::create_common_config_builder(crypto_config, handshake_type)?;
        builder.load_pem(
            read_to_bytes(SERVER_CERT_CHAIN_PATH).as_slice(),
            read_to_bytes(SERVER_KEY_PATH).as_slice(),
        )?;

        if handshake_type == HandshakeType::MutualAuth {
            builder
                .trust_pem(read_to_bytes(CA_CERT_PATH).as_slice())?
                .set_verify_host_callback(HostNameHandler {
                    expected_server_name: "localhost",
                })?;
        }

        Ok(builder.build()?)
    }

    /// Set up connections with config and custom IO
    fn init_conn(&mut self, mode: Mode) -> Result<(), Box<dyn Error>> {
        let client_to_server_ptr = self.client_to_server_buf.get() as *mut c_void;
        let server_to_client_ptr = self.server_to_client_buf.get() as *mut c_void;
        let (read_ptr, write_ptr, config, conn) = match mode {
            Mode::Client => (
                server_to_client_ptr,
                client_to_server_ptr,
                &self.client_config,
                &mut self.client_conn,
            ),
            Mode::Server => (
                client_to_server_ptr,
                server_to_client_ptr,
                &self.server_config,
                &mut self.server_conn,
            ),
        };

        conn.set_blinding(Blinding::SelfService)?
            .set_config(config.clone())?
            .set_send_callback(Some(Self::send_cb))?
            .set_receive_callback(Some(Self::recv_cb))?;
        unsafe {
            conn.set_send_context(write_ptr)?
                .set_receive_context(read_ptr)?;
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
    fn new(
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Self, Box<dyn Error>> {
        let client_to_server_buf = Box::pin(UnsafeCell::new(VecDeque::new()));
        let server_to_client_buf = Box::pin(UnsafeCell::new(VecDeque::new()));

        let client_config = Self::create_client_config(crypto_config, handshake_type)?;
        let server_config = Self::create_server_config(crypto_config, handshake_type)?;

        let mut harness = Self {
            client_to_server_buf,
            server_to_client_buf,
            client_config,
            server_config,
            client_conn: Connection::new_client(),
            server_conn: Connection::new_server(),
            client_handshake_completed: false,
            server_handshake_completed: false,
        };

        harness.init_conn(Mode::Client)?;
        harness.init_conn(Mode::Server)?;

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

    fn send(&mut self, sender: Mode, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let send_conn = match sender {
            Mode::Client => &mut self.client_conn,
            Mode::Server => &mut self.server_conn,
        };

        assert!(send_conn.poll_send(data).is_ready());
        assert!(send_conn.poll_flush().is_ready());

        Ok(())
    }

    fn recv(&mut self, receiver: Mode, data: &mut [u8]) -> Result<(), Box<dyn Error>> {
        let recv_conn = match receiver {
            Mode::Client => &mut self.client_conn,
            Mode::Server => &mut self.server_conn,
        };

        assert!(recv_conn.poll_recv(data).is_ready());
        Ok(())
    }
}
