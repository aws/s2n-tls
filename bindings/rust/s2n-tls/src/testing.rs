// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{callbacks::VerifyHostNameCallback, config::*, security, testing::s2n_tls::Harness};
use alloc::{collections::VecDeque, sync::Arc};
use bytes::Bytes;
use core::{
    sync::atomic::{AtomicUsize, Ordering},
    task::Poll,
};

pub mod client_hello;
pub mod s2n_tls;

type Error = Box<dyn std::error::Error>;
type Result<T, E = Error> = core::result::Result<T, E>;

/// The number of iterations that will be executed until the handshake exits with an error
///
/// This is to prevent endless looping without making progress on the connection.
const SAMPLES: usize = 100;

pub fn test_error(msg: &str) -> crate::error::Error {
    crate::error::Error::application(msg.into())
}

pub fn assert_test_error(input: Error, msg: &str) {
    let error = input
        .downcast::<crate::error::Error>()
        .expect("Unexpected generic error type");
    if let Some(inner) = error.application_error() {
        assert_eq!(msg, inner.to_string())
    } else {
        panic!("Unexpected known error type");
    }
}

#[derive(Clone)]
pub struct Counter(Arc<AtomicUsize>);
impl Counter {
    fn new() -> Self {
        Counter(Arc::new(AtomicUsize::new(0)))
    }
    pub fn count(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
    pub fn increment(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

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

#[derive(Default)]
pub struct UnsecureAcceptAllClientCertificatesHandler {}
impl VerifyHostNameCallback for UnsecureAcceptAllClientCertificatesHandler {
    fn verify_host_name(&self, _host_name: &str) -> bool {
        true
    }
}

pub fn build_config(cipher_prefs: &security::Policy) -> Result<crate::config::Config, Error> {
    let builder = config_builder(cipher_prefs)?;
    Ok(builder.build().expect("Unable to build server config"))
}

pub fn config_builder(cipher_prefs: &security::Policy) -> Result<crate::config::Builder, Error> {
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
        builder
            .set_verify_host_callback(UnsecureAcceptAllClientCertificatesHandler::default())
            .expect("Unable to set a host verify callback.");
        builder
            .disable_x509_verification()
            .expect("Unable to disable x509 verification");
    };
    Ok(builder)
}

pub fn s2n_tls_pair(config: crate::config::Config) {
    // create and configure a server connection
    let mut server = crate::connection::Connection::new_server();
    server
        .set_config(config.clone())
        .expect("Failed to bind config to server connection");
    let server = Harness::new(server);

    // create a client connection
    let mut client = crate::connection::Connection::new_client();
    client
        .set_config(config)
        .expect("Unable to set client config");
    let client = Harness::new(client);

    let pair = Pair::new(server, client, SAMPLES);
    poll_tls_pair(pair);
}

pub fn poll_tls_pair(mut pair: Pair<Harness, Harness>) -> Pair<Harness, Harness> {
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

    pair
}

pub fn poll_tls_pair_result(mut pair: Pair<Harness, Harness>) -> Result<()> {
    loop {
        match pair.poll() {
            Poll::Ready(result) => return result,
            Poll::Pending => continue,
        }
    }
}
