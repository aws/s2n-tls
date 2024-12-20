// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    callbacks::VerifyHostNameCallback,
    cert_chain::{self, CertificateChain},
    config::{self, *},
    connection,
    enums::{self, Blinding},
    error, security,
};
use alloc::{collections::VecDeque, sync::Arc};

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

pub fn assert_test_error(input: crate::error::Error, expected_message: &str) {
    let error_msg = input
        .application_error()
        .expect("unexpected error type")
        .to_string();
    assert_eq!(expected_message, error_msg.to_string())
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

#[allow(non_camel_case_types)]
// allow non camel case types because the mixture of letters and numbers is easier
// to read with snake_case.
pub enum SniTestCerts {
    AlligatorRsa,
    AlligatorEcdsa,
    BeaverRsa,
}

impl SniTestCerts {
    pub fn get(&self) -> CertKeyPair {
        let prefix = match *self {
            SniTestCerts::AlligatorRsa => "alligator_",
            SniTestCerts::AlligatorEcdsa => "alligator_ecdsa_",
            SniTestCerts::BeaverRsa => "beaver_",
        };
        CertKeyPair::from_path(&format!("sni/{prefix}"), "cert", "key", "cert")
    }
}

pub struct CertKeyPair {
    cert_path: String,
    key_path: String,
    ca_path: String,
    cert: Vec<u8>,
    key: Vec<u8>,
}

impl Default for CertKeyPair {
    fn default() -> Self {
        Self::from_path("rsa_4096_sha512_client_", "cert", "key", "cert")
    }
}

impl CertKeyPair {
    /// This is the directory holding all of the pems used for s2n-tls unit tests
    const TEST_PEMS_PATH: &'static str =
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../../../tests/pems/");

    /// Create a test CertKeyPair
    /// * `prefix`: The *relative* prefix from the s2n-tls/tests/pems/ folder.
    /// * `chain`: The suffix indicate the full chain.
    /// * `key`: The suffix indicate the private key.
    /// * `ca`: The suffix indicating the CA.
    ///
    /// ### Example
    /// Assuming the relevant files are at
    /// - s2n-tls/tests/pems/permutations/rsae_pkcs_4096_sha384/server-chain.pem
    /// - s2n-tls/tests/pems/permutations/rsae_pkcs_4096_sha384/server-key.pem
    /// - s2n-tls/tests/pems/permutations/rsae_pkcs_4096_sha384/ca-cert.pem
    ///
    /// ```ignore
    /// let cert = CertKeyPair::from(
    ///     "permutations/rsae_pkcs_4096_sha384/",
    ///     "server-chain",
    ///     "server-key",
    ///     "ca-cert"
    /// );
    /// ```
    pub fn from_path(prefix: &str, chain: &str, key: &str, ca: &str) -> Self {
        let cert_path = format!("{}{prefix}{chain}.pem", Self::TEST_PEMS_PATH);
        println!("{:?}", cert_path);
        let key_path = format!("{}{prefix}{key}.pem", Self::TEST_PEMS_PATH);
        let ca_path = format!("{}{prefix}{ca}.pem", Self::TEST_PEMS_PATH);
        let cert = std::fs::read(&cert_path)
            .unwrap_or_else(|_| panic!("Failed to read cert at {cert_path}"));
        let key =
            std::fs::read(&key_path).unwrap_or_else(|_| panic!("Failed to read key at {key_path}"));
        CertKeyPair {
            cert_path,
            key_path,
            ca_path,
            cert,
            key,
        }
    }

    pub fn into_certificate_chain(&self) -> CertificateChain<'static> {
        let mut chain = cert_chain::Builder::new().unwrap();
        chain.load_pem(&self.cert, &self.key).unwrap();
        chain.build().unwrap()
    }

    pub fn cert_path(&self) -> &str {
        &self.cert_path
    }

    pub fn key_path(&self) -> &str {
        &self.key_path
    }

    pub fn ca_path(&self) -> &str {
        &self.ca_path
    }

    pub fn cert(&self) -> &[u8] {
        &self.cert
    }

    pub fn key(&self) -> &[u8] {
        &self.key
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

type LocalDataBuffer = RefCell<VecDeque<u8>>;

#[derive(Debug)]
// We allow dead_code, because otherwise the compiler complains about the tx_streams
// never being read. This is because it can't reason through the pointers that were
// passed into the s2n-tls connection io contexts.
#[allow(dead_code)]
pub struct TestPairIO {
    // Pin: since we are dereferencing this pointer (because it is passed as the send/recv ctx)
    // we need to ensure that the pointer remains in the same place
    // Box: A Vec (or VecDeque) may be moved or reallocated, so we need another layer of
    // indirection to have a stable (pinned) reference
    /// a data buffer that the server writes to and the client reads from
    pub server_tx_stream: Pin<Box<LocalDataBuffer>>,
    /// a data buffer that the client writes to and the server reads from
    pub client_tx_stream: Pin<Box<LocalDataBuffer>>,
}

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
pub struct TestPair {
    pub server: connection::Connection,
    pub client: connection::Connection,
    pub io: TestPairIO,
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
        // import in smallest namespace to avoid collision with config::Builder;
        use crate::connection::Builder;

        let client = client_config.build_connection(enums::Mode::Client).unwrap();
        let server = server_config.build_connection(enums::Mode::Server).unwrap();

        Self::from_connections(client, server)
    }

    pub fn from_connections(
        mut client: connection::Connection,
        mut server: connection::Connection,
    ) -> Self {
        let client_tx_stream = Box::pin(Default::default());
        let server_tx_stream = Box::pin(Default::default());

        Self::register_connection(&mut client, &client_tx_stream, &server_tx_stream).unwrap();

        Self::register_connection(&mut server, &server_tx_stream, &client_tx_stream).unwrap();

        let io = TestPairIO {
            server_tx_stream,
            client_tx_stream,
        };
        Self { server, client, io }
    }

    /// create a connection ready for harness IO
    ///
    /// This mostly consists of setting the IO callbacks and the IO contexts.
    ///
    /// We also set blinding to "SelfService" to avoid long delays after failures
    /// in unit tests. However, this will cause calls to `poll_shutdown` to return
    /// Poll::Pending until the blinding delay elapses.
    fn register_connection(
        conn: &mut connection::Connection,
        send_ctx: &Pin<Box<LocalDataBuffer>>,
        recv_ctx: &Pin<Box<LocalDataBuffer>>,
    ) -> Result<(), error::Error> {
        conn.set_blinding(Blinding::SelfService)?
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
        Ok(())
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
                // not ready, poll again
                _ => {}
            }
        }
    }

    pub(crate) unsafe extern "C" fn send_cb(
        context: *mut c_void,
        data: *const u8,
        len: u32,
    ) -> c_int {
        let context = &*(context as *const LocalDataBuffer);
        let data = core::slice::from_raw_parts(data, len as _);
        let bytes_written = context.borrow_mut().write(data).unwrap();
        bytes_written as c_int
    }

    // Note: this callback will be invoked multiple times in the event that
    // the byte-slices of the VecDeque are not contiguous (wrap around).
    pub(crate) unsafe extern "C" fn recv_cb(
        context: *mut c_void,
        data: *mut u8,
        len: u32,
    ) -> c_int {
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
