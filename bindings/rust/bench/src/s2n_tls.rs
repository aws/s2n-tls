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
    cell::UnsafeCell,
    collections::VecDeque,
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
    fn handshake_conn(&mut self, mode: Mode) {
        let (conn, handshake_completed) = match mode {
            Mode::Client => {
                debug!("Client: ");
                (&mut self.client_conn, &mut self.client_handshake_completed)
            }
            Mode::Server => {
                debug!("Server: ");
                (&mut self.server_conn, &mut self.server_handshake_completed)
            }
        };

        if let Ready(res) = conn.poll_negotiate() {
            res.unwrap();
            *handshake_completed = true;
        } else {
            *handshake_completed = false;
        }
    }
}

impl TlsBenchHarness for S2NHarness {
    fn new() -> Self {
        debug!("----- constructing new s2n-tls harness -----");
        let mut harness = S2NHarness {
            client_to_server_buf: Box::pin(UnsafeCell::new(VecDeque::new())),
            server_to_client_buf: Box::pin(UnsafeCell::new(VecDeque::new())),
            client_config: Self::create_config(Mode::Client),
            server_config: Self::create_config(Mode::Server),
            client_conn: Connection::new_client(),
            server_conn: Connection::new_server(),
            client_handshake_completed: false,
            server_handshake_completed: false,
        };
        harness.init_conn(Mode::Client).unwrap();
        harness.init_conn(Mode::Server).unwrap();
        harness
    }

    fn handshake(&mut self) -> Result<(), &str> {
        if self.handshake_completed() {
            return Err("Already completed handshake");
        }
        debug!("HANDSHAKE");
        let mut round_trips = 2; // expect two round trips, second for server to see Finished message
        while round_trips > 0 {
            self.handshake_conn(Mode::Client);
            self.handshake_conn(Mode::Server);
            round_trips -= 1;
        }
        debug!("HANDSHAKE DONE\n");
        Ok(())
    }

    fn handshake_completed(&self) -> bool {
        self.client_handshake_completed && self.server_handshake_completed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s2n_tls_create_object() {
        S2NHarness::new();
    }

    #[test]
    fn s2n_tls_handshake_successful() {
        let mut s2n_tls_harness = S2NHarness::new();
        assert!(!s2n_tls_harness.handshake_completed());
        assert!(s2n_tls_harness.handshake().is_ok());
        assert!(s2n_tls_harness.handshake_completed());
        assert!(s2n_tls_harness.handshake().is_err()); // make sure doesn't panic
    }
}
