// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    raw::{config::*, security},
    testing::s2n_tls::Harness,
};
use alloc::sync::Arc;
use bytes::Bytes;
use core::task::{Poll, Waker};
use std::{collections::VecDeque, task::Wake};

pub mod s2n_tls;

type Error = Box<dyn std::error::Error>;
type Result<T, E = Error> = core::result::Result<T, E>;

/// The number of iterations that will be executed until the handshake exits with an error
///
/// This is to prevent endless looping without making progress on the connection.
const SAMPLES: usize = 100;

pub trait Connection: core::fmt::Debug {
    fn poll<Ctx: Context>(&mut self, context: &mut Ctx) -> Poll<Result<()>>;
}

pub trait Context {
    fn receive(&mut self, max_len: Option<usize>) -> Option<Bytes>;
    fn send(&mut self, data: Bytes);
}

#[derive(Debug)]
pub struct Pair<Server: Connection, Client: Connection> {
    pub server: (Server, MemoryContext),
    pub client: (Client, MemoryContext),
    pub max_iterations: usize,
}

impl<Server: Connection, Client: Connection> Pair<Server, Client> {
    pub fn new(server: Server, client: Client, max_iterations: usize) -> Self {
        Self {
            server: (server, Default::default()),
            client: (client, Default::default()),
            max_iterations,
        }
    }
    pub fn poll(&mut self) -> Poll<Result<()>> {
        assert!(
            self.max_iterations > 0,
            "handshake has iterated too many times: {:#?}",
            self,
        );
        let client_res = self.client.0.poll(&mut self.client.1);
        let server_res = self.server.0.poll(&mut self.server.1);
        self.client.1.transfer(&mut self.server.1);
        self.max_iterations -= 1;
        match (client_res, server_res) {
            (Poll::Ready(client_res), Poll::Ready(server_res)) => {
                client_res?;
                server_res?;
                Ok(()).into()
            }
            (Poll::Ready(client_res), _) => {
                client_res?;
                Poll::Pending
            }
            (_, Poll::Ready(server_res)) => {
                server_res?;
                Poll::Pending
            }
            _ => Poll::Pending,
        }
    }
}

#[derive(Debug, Default)]
pub struct MemoryContext {
    rx: VecDeque<Bytes>,
    tx: VecDeque<Bytes>,
}

impl MemoryContext {
    pub fn transfer(&mut self, other: &mut Self) {
        self.rx.extend(other.tx.drain(..));
        other.rx.extend(self.tx.drain(..));
    }
}

impl Context for MemoryContext {
    fn receive(&mut self, max_len: Option<usize>) -> Option<Bytes> {
        loop {
            let mut chunk = self.rx.pop_front()?;

            if chunk.is_empty() {
                continue;
            }

            let max_len = max_len.unwrap_or(usize::MAX);

            if chunk.len() > max_len {
                self.rx.push_front(chunk.split_off(max_len));
            }

            return Some(chunk);
        }
    }

    fn send(&mut self, data: Bytes) {
        self.tx.push_back(data);
    }
}

struct CertKeyPair {
    cert: &'static [u8],
    key: &'static [u8],
}

impl Default for CertKeyPair {
    fn default() -> Self {
        CertKeyPair {
            cert: &include_bytes!("../../../../tests/pems/rsa_4096_sha512_client_cert.pem")[..],
            key: &include_bytes!("../../../../tests/pems/rsa_4096_sha512_client_key.pem")[..],
        }
    }
}

impl CertKeyPair {
    fn cert(&mut self) -> &'static [u8] {
        self.cert
    }

    fn key(&mut self) -> &'static [u8] {
        self.key
    }
}

pub fn build_config(cipher_prefs: &security::Policy) -> Result<crate::raw::config::Config, Error> {
    let mut builder = Builder::new();
    let mut keypair = CertKeyPair::default();
    // Build a config
    builder
        .set_security_policy(cipher_prefs)
        .expect("Unable to set config cipher preferences");
    builder
        .load_pem(keypair.cert(), keypair.key())
        .expect("Unable to load cert/pem");
    unsafe {
        let ctx: *mut core::ffi::c_void = std::ptr::null_mut();
        builder
            .set_verify_host_callback(Some(verify_host_cb), ctx)
            .expect("Unable to set a host verify callback.");
        builder
            .disable_x509_verification()
            .expect("Unable to disable x509 verification");
    };
    Ok(builder.build().expect("Unable to build server config"))
}

// host verify callback for x509
// see: https://github.com/aws/s2n-tls/blob/main/docs/USAGE-GUIDE.md#s2n_verify_host_fn
unsafe extern "C" fn verify_host_cb(
    hostname: *const i8,
    hostname_len: usize,
    _context: *mut core::ffi::c_void,
) -> u8 {
    let host_str = ::std::str::from_utf8(::std::slice::from_raw_parts(
        hostname as *const u8,
        hostname_len,
    ));
    match host_str {
        Err(_) => 0,
        Ok(_host) => 1,
    }
}

pub fn s2n_tls_pair(config: crate::raw::config::Config) {
    // create and configure a server connection
    let mut server = crate::raw::connection::Connection::new_server();
    server
        .set_config(config.clone())
        .expect("Failed to bind config to server connection");
    server
        .set_client_auth_type(s2n_tls_sys::s2n_cert_auth_type::NONE)
        .expect("Unable to set server client auth type");
    let server = Harness::new(server);

    // create a client connection
    let mut client = crate::raw::connection::Connection::new_client();
    client
        .set_config(config)
        .expect("Unabel to set client config");
    let client = Harness::new(client);

    let mut pair = Pair::new(server, client, SAMPLES);
    loop {
        match pair.poll() {
            Poll::Ready(result) => {
                result.unwrap();
                break;
            }
            Poll::Pending => continue,
        }
    }

    // TODO add assertions to make sure the handshake actually succeeded
}

struct TestWaker {}

impl Wake for TestWaker {
    fn wake(self: Arc<Self>) {}
}

impl TestWaker {
    pub fn get_waker() -> Waker {
        let data = Arc::new(TestWaker {});
        Waker::from(data)
    }
}
