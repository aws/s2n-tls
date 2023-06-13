// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    harness::{read_to_bytes, Mode, TlsBenchHarness},
    CA_CERT_PATH, SERVER_CERT_CHAIN_PATH, SERVER_KEY_PATH,
};
use log::debug;
use s2n_tls::{
    callbacks::VerifyHostNameCallback,
    config::{Builder, Config},
    connection::Connection,
    enums::Blinding,
    security::DEFAULT_TLS13,
};
use std::{
    collections::VecDeque,
    ffi::c_void,
    io::{Read, Write},
    os::raw::c_int,
    pin::Pin,
    task::Poll::Ready,
};

pub struct S2nTls {
    client_to_server_buf: Pin<Box<VecDeque<u8>>>, // Pinned pointer to a VecDeque to pass as C pointer for custom IO
    server_to_client_buf: Pin<Box<VecDeque<u8>>>,
    client_config: Config,
    server_config: Config,
    client_conn: Connection,
    server_conn: Connection,
    client_handshaked: bool,
    server_handshaked: bool,
}

/// Custom callback for verifying hostnames, need it to use s2n-tls safely
struct HostNameHandler<'a> {
    expected_server_name: &'a str,
}
impl VerifyHostNameCallback for HostNameHandler<'_> {
    fn verify_host_name(&self, hostname: &str) -> bool {
        self.expected_server_name == hostname
    }
}

impl S2nTls {
    /// Unsafe callback for custom IO C API
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
            debug!("\t[blocking]");
            errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
            -1
        } else {
            debug!("\t- received {len}");
            len as _
        }
    }

    fn create_config(mode: Mode) -> Config {
        let mut builder = Builder::new();
        builder.set_security_policy(&DEFAULT_TLS13).unwrap();

        match mode {
            Mode::Server => builder
                .load_pem(
                    read_to_bytes(SERVER_CERT_CHAIN_PATH).as_slice(),
                    read_to_bytes(SERVER_KEY_PATH).as_slice(),
                )
                .unwrap(),
            Mode::Client => builder
                .trust_pem(read_to_bytes(CA_CERT_PATH).as_slice())
                .unwrap()
                .set_verify_host_callback(HostNameHandler {
                    expected_server_name: "localhost",
                })
                .unwrap(),
        };

        builder.build().unwrap()
    }

    /// Set up connections with config and custom IO
    fn init_conn(&mut self, mode: Mode) -> Result<(), s2n_tls::error::Error> {
        let client_to_server_ptr =
            &mut self.client_to_server_buf as &mut VecDeque<u8> as *mut VecDeque<u8> as *mut c_void;
        let server_to_client_ptr =
            &mut self.server_to_client_buf as &mut VecDeque<u8> as *mut VecDeque<u8> as *mut c_void;
        let (read_ptr, write_ptr, config, conn);

        match mode {
            Mode::Client => {
                read_ptr = server_to_client_ptr;
                write_ptr = client_to_server_ptr;
                config = &self.client_config;
                conn = &mut self.client_conn;
            }
            Mode::Server => {
                read_ptr = client_to_server_ptr;
                write_ptr = server_to_client_ptr;
                config = &self.server_config;
                conn = &mut self.server_conn;
            }
        }

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
    fn handshake_conn(&mut self, mode: Mode) {
        let (conn, handshaked);
        match mode {
            Mode::Client => {
                debug!("Client: ");
                conn = &mut self.client_conn;
                handshaked = &mut self.client_handshaked;
            }
            Mode::Server => {
                debug!("Server: ");
                conn = &mut self.server_conn;
                handshaked = &mut self.server_handshaked;
            }
        }
        if let Ready(res) = conn.poll_negotiate() {
            res.unwrap();
            *handshaked = true;
        } else {
            *handshaked = false;
        }
    }
}

impl TlsBenchHarness for S2nTls {
    fn new() -> Self {
        debug!("----- s2n-tls -----");
        let mut new_struct = S2nTls {
            client_to_server_buf: Box::pin(VecDeque::new()),
            server_to_client_buf: Box::pin(VecDeque::new()),
            client_config: Self::create_config(Mode::Client),
            server_config: Self::create_config(Mode::Server),
            client_conn: Connection::new_client(),
            server_conn: Connection::new_server(),
            client_handshaked: false,
            server_handshaked: false,
        };
        new_struct.init_conn(Mode::Client).unwrap();
        new_struct.init_conn(Mode::Server).unwrap();
        new_struct
    }

    fn handshake(&mut self) {
        if self.has_handshaked() {
            return;
        }
        debug!("HANDSHAKE");
        let mut round_trips = 2; // expect two round trips, second for server to see Finished message
        while !self.has_handshaked() && round_trips > 0 {
            self.handshake_conn(Mode::Client);
            self.handshake_conn(Mode::Server);
            round_trips -= 1;
        }
        debug!("HANDSHAKE DONE\n");
    }

    fn has_handshaked(&self) -> bool {
        self.client_handshaked && self.server_handshaked
    }
}

#[cfg(test)]
mod tests {
    use crate::TlsBenchHarness;

    #[test]
    fn s2n_tls_create_object() {
        super::S2nTls::new();
    }

    #[test]
    fn s2n_tls_handshake_successful() {
        let mut s2n_tls_harness = super::S2nTls::new();
        assert!(!s2n_tls_harness.has_handshaked());
        s2n_tls_harness.handshake();
        assert!(s2n_tls_harness.has_handshaked());
        s2n_tls_harness.handshake(); // make sure doesn't panic
    }
}
