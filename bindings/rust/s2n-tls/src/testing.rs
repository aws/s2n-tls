// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    callbacks::VerifyHostNameCallback,
    config::{self, *},
    connection,
    enums::{self, Blinding},
    error, security,
    testing::s2n_tls::Harness,
};
use alloc::{collections::VecDeque, sync::Arc};
use bytes::Bytes;
use core::{
    sync::atomic::{AtomicUsize, Ordering},
    task::Poll,
};
use libc::{c_int, c_void};
use std::{
    cell::RefCell,
    io::{Read, Write},
    pin::Pin,
};

pub mod client_hello;
pub mod resumption;
pub mod s2n_tls;

type Error = Box<dyn std::error::Error>;
type Result<T, E = Error> = core::result::Result<T, E>;

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
    fn poll_negotiate<Ctx: Context>(&mut self, context: &mut Ctx) -> Poll<Result<()>>;
    fn poll_action<Ctx: Context, F>(&mut self, context: &mut Ctx, action: F) -> Poll<Result<()>>
    where
        F: FnOnce(&mut connection::Connection) -> Poll<Result<usize, crate::error::Error>>;
}

pub trait Context {
    fn receive(&mut self, max_len: Option<usize>) -> Option<Bytes>;
    fn send(&mut self, data: Bytes);
}

pub enum Mode {
    Client,
    Server,
}

#[derive(Debug)]
pub struct Pair<Server: Connection, Client: Connection> {
    pub server: (Server, MemoryContext),
    pub client: (Client, MemoryContext),
    pub max_iterations: usize,
}

impl<Server: Connection, Client: Connection> Pair<Server, Client> {
    /// The number of iterations that will be executed until the handshake exits with an error
    ///
    /// This is to prevent endless looping without making progress on the connection.
    const DEFAULT_ITERATIONS: usize = 100;

    pub fn new(server: Server, client: Client) -> Self {
        Self {
            server: (server, Default::default()),
            client: (client, Default::default()),
            max_iterations: Self::DEFAULT_ITERATIONS,
        }
    }
    pub fn poll(&mut self) -> Poll<Result<()>> {
        assert!(
            self.max_iterations > 0,
            "handshake has iterated too many times: {:#?}",
            self,
        );
        let client_res = self.client.0.poll_negotiate(&mut self.client.1);
        let server_res = self.server.0.poll_negotiate(&mut self.server.1);
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

    pub fn poll_send(&mut self, sender: Mode, buf: &[u8]) -> Poll<Result<()>> {
        let result = match sender {
            Mode::Client => self.client.0.poll_action(&mut self.client.1, |conn| {
                connection::Connection::poll_send(conn, buf)
            }),
            Mode::Server => self.server.0.poll_action(&mut self.server.1, |conn| {
                connection::Connection::poll_send(conn, buf)
            }),
        };
        self.server.1.transfer(&mut self.client.1);
        match result {
            Poll::Ready(result) => {
                result?;
                Ok(()).into()
            }
            Poll::Pending => Poll::Pending,
        }
    }

    pub fn poll_recv(&mut self, receiver: Mode, buf: &mut [u8]) -> Poll<Result<()>> {
        let result = match receiver {
            Mode::Client => self.client.0.poll_action(&mut self.client.1, |conn| {
                connection::Connection::poll_recv(conn, buf)
            }),
            Mode::Server => self.server.0.poll_action(&mut self.server.1, |conn| {
                connection::Connection::poll_recv(conn, buf)
            }),
        };
        match result {
            Poll::Ready(result) => {
                result?;
                Ok(()).into()
            }
            Poll::Pending => Poll::Pending,
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

pub struct CertKeyPair {
    cert_path: &'static str,
    cert: &'static [u8],
    key: &'static [u8],
}

impl Default for CertKeyPair {
    fn default() -> Self {
        CertKeyPair {
            cert_path: concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../tests/pems/rsa_4096_sha512_client_cert.pem",
            ),
            cert: &include_bytes!("../../../../tests/pems/rsa_4096_sha512_client_cert.pem")[..],
            key: &include_bytes!("../../../../tests/pems/rsa_4096_sha512_client_key.pem")[..],
        }
    }
}

impl CertKeyPair {
    pub fn cert_path(&self) -> &'static str {
        self.cert_path
    }

    pub fn cert(&self) -> &'static [u8] {
        self.cert
    }

    pub fn key(&self) -> &'static [u8] {
        self.key
    }
}

pub struct InsecureAcceptAllCertificatesHandler {}
impl VerifyHostNameCallback for InsecureAcceptAllCertificatesHandler {
    fn verify_host_name(&self, _host_name: &str) -> bool {
        true
    }
}

pub struct RejectAllCertificatesHandler {}
impl VerifyHostNameCallback for RejectAllCertificatesHandler {
    fn verify_host_name(&self, _host_name: &str) -> bool {
        false
    }
}

pub fn build_config(cipher_prefs: &security::Policy) -> Result<crate::config::Config, Error> {
    let builder = config_builder(cipher_prefs)?;
    Ok(builder.build().expect("Unable to build server config"))
}

pub fn config_builder(cipher_prefs: &security::Policy) -> Result<crate::config::Builder, Error> {
    let mut builder = Builder::new();
    let keypair = CertKeyPair::default();
    // Build a config
    builder
        .set_security_policy(cipher_prefs)
        .expect("Unable to set config cipher preferences");
    builder
        .load_pem(keypair.cert(), keypair.key())
        .expect("Unable to load cert/pem");
    builder
        .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
        .expect("Unable to set a host verify callback.");
    builder.trust_pem(keypair.cert()).expect("load cert pem");
    Ok(builder)
}

pub fn tls_pair(config: crate::config::Config) -> Pair<Harness, Harness> {
    // create and configure a server connection
    let mut server = crate::connection::Connection::new_server();
    // some tests check for connection failure so disable blinding to avoid delay
    server.as_mut().set_blinding(Blinding::SelfService).unwrap();
    server
        .set_config(config.clone())
        .expect("Failed to bind config to server connection");
    let server = Harness::new(server);

    // create a client connection
    let mut client = crate::connection::Connection::new_client();
    // some tests check for connection failure so disable blinding to avoid delay
    client.as_mut().set_blinding(Blinding::SelfService).unwrap();
    client
        .set_config(config)
        .expect("Unable to set client config");
    let client = Harness::new(client);

    Pair::new(server, client)
}

pub fn establish_connection(config: crate::config::Config) {
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

    let pair = Pair::new(server, client);
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

    pair
}

pub fn poll_tls_pair_result(pair: &mut Pair<Harness, Harness>) -> Result<()> {
    loop {
        match pair.poll() {
            Poll::Ready(result) => return result,
            Poll::Pending => continue,
        }
    }
}

type LocalDataBuffer = RefCell<VecDeque<u8>>;

/// TestPair is a testing utility used to easily test handshakes and send data.
///
/// SAFETY: if the server or client connection is moved outside of the struct, IO
/// is not safe to perform. The connections use pointers to data buffers owned by
/// the Harness. If the Harness goes out of scope, the data buffers will be dropped
/// and the pointers will be invalid.
///
/// The most common usecase is handshaking a simple config.
/// ```ignore
/// // given some config
/// let config = build_config(&crate::security::DEFAULT_TLS13).unwrap();
/// // create a pair (client + server) with uses that config
/// let mut pair = TestPair::from_config(&config);
/// // assert a successful handshake
/// assert!(pair.handshake().is_ok());
/// // we can also do IO using the poll_* functions
/// // this data is sent using the shared data buffers owned by the harness
/// assert!(pair.server.poll_send(&[3, 1, 4]).is_ready());
/// let mut buffer = [0; 3];
/// assert!(pair.client.poll_recv(&mut buffer).is_ready());
/// assert_eq!([3, 1, 4], buffer);
/// ```
//
// The doctest is `ignore`d because testing utilities are not publicly exported
// and therefore can't be referenced in a doc comment.
//
// We allow dead_code, because otherwise the compiler complains about the tx_streams
// never being read. This is because it can't reason through the pointers that were
// passed into the s2n-tls connection io contexts.
#[allow(dead_code)]
pub struct TestPair {
    pub server: connection::Connection,
    pub client: connection::Connection,

    // Pin: since we are dereferencing this pointer (because it is passed as the send/recv ctx)
    // we need to ensure that the pointer remains in the same place
    // Box: A Vec (or VecDeque) may be moved or reallocated, so we need another layer of
    // indirection to have a stable (pinned) reference
    /// a data buffer that the server writes to and the client reads from
    server_tx_stream: Pin<Box<LocalDataBuffer>>,
    /// a data buffer that the client writes to and the server reads from
    client_tx_stream: Pin<Box<LocalDataBuffer>>,
}

impl TestPair {
    /// utility method to test simple handshakes
    ///
    /// Create a client and server from the associated `config`, and try to complete
    /// a TLS handshake. The result of the handshake is returned.
    pub fn handshake_with_config(config: &config::Config) -> Result<(), error::Error> {
        Self::from_configs(config, config).handshake()
    }

    /// create a pair from a config
    ///
    /// A server and client connection will be created, and both will be associated
    /// with `config`. The connections will be setup for IO over shared memory,
    /// but no IO is performed. To handshake the connections, call `handshake()`.
    pub fn from_config(config: &config::Config) -> Self {
        Self::from_configs(config, config)
    }

    pub fn from_configs(client_config: &config::Config, server_config: &config::Config) -> Self {
        let client_tx_stream = Box::pin(Default::default());
        let server_tx_stream = Box::pin(Default::default());

        let client = Self::register_connection(
            enums::Mode::Client,
            client_config,
            &client_tx_stream,
            &server_tx_stream,
        )
        .unwrap();

        let server = Self::register_connection(
            enums::Mode::Server,
            server_config,
            &server_tx_stream,
            &client_tx_stream,
        )
        .unwrap();

        Self {
            server,
            client,
            server_tx_stream,
            client_tx_stream,
        }
    }

    /// create a connection ready for harness IO
    ///
    /// This mostly consists of setting the IO callbacks and the IO contexts.
    ///
    /// We also set blinding to "SelfService" to avoid long delays after failures
    /// in unit tests. However, this will cause calls to `poll_shutdown` to return
    /// Poll::Pending until the blinding delay elapses.
    fn register_connection(
        mode: enums::Mode,
        config: &config::Config,
        send_ctx: &Pin<Box<LocalDataBuffer>>,
        recv_ctx: &Pin<Box<LocalDataBuffer>>,
    ) -> Result<connection::Connection, error::Error> {
        let mut conn = connection::Connection::new(mode);
        conn.set_config(config.clone())?
            .set_blinding(Blinding::SelfService)?
            .set_send_callback(Some(Self::send_cb))?
            .set_receive_callback(Some(Self::recv_cb))?;
        unsafe {
            // cast 1 : send_ctx as &LocalDataBuffer -> get a plain reference to underlying LocalDataBuffer
            //
            // cast 2: &LocalDataBuffer as *const LocalDataBuffer -> cast the reference to a pointer
            //     SAFETY: the LocalDataBuffer must live as long as the connection does. This can be violated if the
            //             connections are moved out from the struct.
            //
            // cast 3: *const LocalDataBuffer as *mut c_void -> cast into the final *mut c_void required
            //     SAFETY: serialized access is enforced by the interior RefCell, so it is safe to vend out
            //             multiple mutable pointers to this item. We ensure this by casting back to an immutable
            //             reference in the send and recv callbacks
            conn.set_send_context(
                send_ctx as &LocalDataBuffer as *const LocalDataBuffer as *mut c_void,
            )?
            .set_receive_context(
                recv_ctx as &LocalDataBuffer as *const LocalDataBuffer as *mut c_void,
            )?;
        }
        Ok(conn)
    }

    /// perform a TLS handshake between the connections
    ///
    /// This method will call `poll_negotiate` on each connection until both return
    /// Ready(Ok) which indicates a successful handshake, or until one of the connections
    /// returns Ready(Err) which indicates some fatal error.
    pub fn handshake(&mut self) -> Result<(), error::Error> {
        loop {
            match (self.client.poll_negotiate(), self.server.poll_negotiate()) {
                // if everything is finished and Ok, return Ok
                (Poll::Ready(Ok(_)), Poll::Ready(Ok(_))) => return Ok(()),
                // if there has been an error on the server
                (_, Poll::Ready(Err(e))) => return Err(e),
                // or an error on the client, then return the error
                (Poll::Ready(Err(e)), _) => return Err(e),
                _ => { /* not ready, poll again */ }
            }
        }
    }

    unsafe extern "C" fn send_cb(context: *mut c_void, data: *const u8, len: u32) -> c_int {
        let context = &*(context as *const LocalDataBuffer);
        let data = core::slice::from_raw_parts(data, len as _);
        let bytes_written = context.borrow_mut().write(data).unwrap();
        bytes_written as c_int
    }

    // Note: this callback will be invoked multiple times in the event that
    // the byte-slices of the VecDeque are not contiguous (wrap around).
    unsafe extern "C" fn recv_cb(context: *mut c_void, data: *mut u8, len: u32) -> c_int {
        let context = &*(context as *const LocalDataBuffer);
        let data = core::slice::from_raw_parts_mut(data, len as _);
        match context.borrow_mut().read(data) {
            Ok(len) => {
                if len == 0 {
                    // returning a length of 0 indicates a channel close (e.g. a
                    // TCP Close) which would not be correct here. To just communicate
                    // that there is no more data, we instead set the errno to
                    // WouldBlock and return -1.
                    errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
                    -1
                } else {
                    len as c_int
                }
            }
            Err(err) => {
                // VecDeque IO Operations should never fail
                panic!("{err:?}");
            }
        }
    }
}
