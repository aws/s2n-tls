// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Methods to perform renegotiation.
//!
//! The use of renegotiation is strongly discouraged.
//! See [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/renegotiate.h)
//! for the primary documentation of the feature.
//!
//! # Scheduled renegotiation
//!
//! The Rust client can automatically renegotiate in response to a server renegotiation
//! request, if an application does not require support for concurrent reads and writes.
//! This feature is intended for applications that follow a standard request/response model.
//!
//! To use scheduled renegotiation, your must set a [`RenegotiateCallback`] that
//! returns [`RenegotiateResponse::Schedule`].
//!
//! If all renegotiation requests will be accepted and no connection-level
//! configuration is required, then [`RenegotiateResponse`] can be used as the
//! RenegotiateCallback. For example:
//! ```
//! use s2n_tls::config::Builder;
//! use s2n_tls::renegotiate::RenegotiateResponse;
//!
//! let mut builder = Builder::new();
//! builder.set_renegotiate_callback(RenegotiateResponse::Schedule);
//! ```
//!
//! If an application needs to conditionally accept renegotiation requests or
//! uses connection-level configuration that will need to be reset after the
//! connection is wiped for renegotiation, then the application will need to
//! implement a custom `RenegotiateCallback`:
//! ```
//! use s2n_tls::config::Builder;
//! use s2n_tls::connection::Connection;
//! use s2n_tls::error::Error;
//! use s2n_tls::renegotiate::{RenegotiateCallback, RenegotiateResponse};
//!
//! struct Callback { };
//!
//! impl RenegotiateCallback for Callback {
//!     fn on_renegotiate_request(
//!         &mut self,
//!         conn: &mut Connection,
//!     ) -> Option<RenegotiateResponse> {
//!         let response = match conn.server_name() {
//!             Some("allowed_to_renegotiate") => RenegotiateResponse::Schedule,
//!             _ => RenegotiateResponse::Reject,
//!         };
//!         Some(response)
//!     }
//!
//!     fn on_renegotiate_wipe(&mut self, conn: &mut Connection) -> Result<(), Error> {
//!         conn.set_application_protocol_preference(Some("http"))?;
//!         Ok(())
//!     }
//! }
//!
//! let mut builder = Builder::new();
//! builder.set_renegotiate_callback(Callback{});
//! ```
//! #### Warning:
//!
//! If you are using s2n-tls via a higher level wrapper like s2n-tls-tokio or
//! s2n-tls-hyper, that wrapper may automatically set connection-level configuration
//! for you. As such wrappers are unlikely to be aware of renegotiation, they will
//! not automatically reset their configuration after the connection is wiped for
//! renegotiation. You may need to handle resetting the configuration yourself
//! via `on_renegotiate_wipe`. If that is not possible, please open an issue.
//!  
//! ## How it works
//!
//! When a call to `poll_recv` receives a renegotiation request, `on_renegotiate_request`
//! will be invoked for the connection's  `RenegotiateCallback`. If `on_renegotiate_request`
//! returns `RenegotiateResponse::Schedule`, then s2n-tls will automatically schedule
//! renegotiation. Once renegotiation begins, calls to `poll_recv` will attempt
//! to renegotiate by wiping the connection, which will trigger `on_renegotiate_wipe`
//! from the connection's `RenegotiateCallback`. After wiping, `poll_recv` will
//! perform a new handshake.
//!
//! #### Warning:
//! While performing the new handshake, `poll_recv` will write, not just read.
//! This may violate assumptions your application is making about IO operations.
//!
//! ## Detailed limitations
//!
//! Specifically, scheduled renegotiation will fail if `poll_send`:
//! 1. is called after the renegotiation request is received from the server.
//! 2. returned `Pending` and has not yet returned `Ready` before the renegotiation
//!    request is received from the server.
//!
//! These limitations are a blocker for an application that supports concurrent
//! reads and writes, or which must support an arbitrary ordering of reads and
//! writes. Custom renegotiation will be required for those use cases.
//!
//! # Custom renegotiation
//!
//! The bindings also provide [`Connection::wipe_for_renegotiate()`] and [`Connection::poll_renegotiate()`]
//! as direct mappings of the C `s2n_renegotiate_wipe` and `s2n_renegotiate` methods.
//! If scheduled renegotiation is insufficient for your use case, you can manually
//! integrate with renegotiation according to the instructions in
//! [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/renegotiate.h).
//! Your `on_renegotiate_request` method would return `RenegotiateResponse::Accept`
//! rather than `RenegotiateResponse::Schedule`.
//!

use s2n_tls_sys::*;

use crate::{
    callbacks::with_context,
    config,
    connection::Connection,
    enums::CallbackResult,
    error::{Error, ErrorType, Fallible, Pollable},
};
use std::task::Poll::{self, Pending, Ready};

/// How to handle a renegotiation request.
///
/// See s2n_renegotiate_response in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/renegotiate.h).
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum RenegotiateResponse {
    Ignore,
    Reject,
    Accept,
    /// The same as `Accept`, but also automatically perform renegotiation
    /// when `poll_recv` is called.
    Schedule,
}

impl From<RenegotiateResponse> for s2n_renegotiate_response::Type {
    fn from(input: RenegotiateResponse) -> s2n_renegotiate_response::Type {
        match input {
            RenegotiateResponse::Ignore => s2n_renegotiate_response::RENEGOTIATE_IGNORE,
            RenegotiateResponse::Reject => s2n_renegotiate_response::RENEGOTIATE_REJECT,
            RenegotiateResponse::Accept => s2n_renegotiate_response::RENEGOTIATE_ACCEPT,
            RenegotiateResponse::Schedule => s2n_renegotiate_response::RENEGOTIATE_ACCEPT,
        }
    }
}

/// Callbacks related to the renegotiation TLS feature.
pub trait RenegotiateCallback: 'static + Send + Sync {
    /// A callback that triggers when the client receives a renegotiation request
    /// (a HelloRequest message) from the server.
    ///
    /// Returning `Some(RenegotiateResponse::Schedule)` will trigger s2n-tls
    /// to automatically wipe the connection and renegotiate.
    ///
    /// Returning "None" will result in the C callback returning an error,
    /// canceling the connection.
    ///
    /// See s2n_renegotiate_request_cb in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/renegotiate.h).
    //
    // This method returns Option instead of Result because the callback has no mechanism
    // for surfacing errors to the application, so Result would be somewhat deceptive.
    fn on_renegotiate_request(
        &mut self,
        connection: &mut Connection,
    ) -> Option<RenegotiateResponse>;

    /// A callback that triggers after the connection is wiped for renegotiation.
    ///
    /// Because renegotiation requires wiping the connection, connection-level
    /// configuration will need to be set again via this callback.
    /// See [`Connection::wipe_for_renegotiate()`] for more information.
    fn on_renegotiate_wipe(&mut self, _connection: &mut Connection) -> Result<(), Error> {
        Ok(())
    }
}

impl RenegotiateCallback for RenegotiateResponse {
    fn on_renegotiate_request(&mut self, _conn: &mut Connection) -> Option<RenegotiateResponse> {
        Some(*self)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct RenegotiateState {
    needs_handshake: bool,
    needs_wipe: bool,
    send_pending: bool,
}

impl Connection {
    fn schedule_renegotiate(&mut self) {
        let state = self.renegotiate_state_mut();
        if !state.needs_handshake {
            state.needs_handshake = true;
            state.needs_wipe = true;
        }
    }

    fn is_renegotiating(&self) -> bool {
        self.renegotiate_state().needs_handshake
    }

    /// Reset the connection so that it can be renegotiated.
    ///
    /// See s2n_renegotiate_wipe in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/renegotiate.h).
    /// The Rust equivalent of the listed connection-specific methods that are NOT wiped are:
    ///  - Methods to set the file descriptors: not currently supported by rust bindings
    ///  - Methods to set the send callback:
    ///    [Connection::set_send_callback()], [Connection::set_send_context()]
    ///  - Methods to set the recv callback:
    ///    [Connection::set_receive_callback()], [Connection::set_receive_context()]
    ///
    /// In addition, the Rust bindings do not wipe:
    /// - The server name: [Connection::set_server_name()]. The s2n-tls-tokio
    ///   TlsConnector sets the server name automatically, so preserving it across
    ///   wipes prevents all users of s2n-tls-tokio from needing a custom callback
    ///   just to maintain consistent behavior.
    /// - The waker: [Connection::set_waker()]. Wiping the waker during a call
    ///   to `poll_send` or `poll_recv` can break IO.
    ///
    /// The set of configuration values that are not wiped may change in the future.
    /// Therefore if you specifically need certain connection configuration values
    /// wiped during renegotiation, then you should wipe them yourself in
    /// [RenegotiateCallback::on_renegotiate_wipe()].
    pub fn wipe_for_renegotiate(&mut self) -> Result<(), Error> {
        // Check for buffered data in order to surface more specific
        // error messages to the application.
        if self.renegotiate_state().send_pending {
            return Err(Error::bindings(
                ErrorType::UsageError,
                "RenegotiateError",
                "Unexpected buffered send data during renegotiate",
            ));
        }

        // Save any state that needs to be preserved.
        // The only real cost of saving state here is complexity. We can't save all
        // connection configuration automatically because in the C library, connection
        // configuration is indistinguishable from C connection state.
        let renegotiate_state = self.renegotiate_state().clone();
        let waker = self.waker().cloned();
        let server_name = self.server_name().map(|name| name.to_owned());

        self.wipe_method(|conn| unsafe { s2n_renegotiate_wipe(conn.as_ptr()).into_result() })?;

        // Restore the saved state
        *self.renegotiate_state_mut() = renegotiate_state;
        self.set_waker(waker.as_ref())?;
        if let Some(server_name) = server_name {
            self.set_server_name(&server_name)?;
        }

        // We trigger the callback last so that the application can modify any
        // preserved configuration (like the server name or waker) if necessary.
        if let Some(mut config) = self.config() {
            if let Some(callback) = config.context_mut().renegotiate.as_mut() {
                callback.on_renegotiate_wipe(self)?;
            }
        }

        self.renegotiate_state_mut().needs_wipe = false;
        Ok(())
    }

    fn poll_renegotiate_raw(
        &mut self,
        buf_ptr: *mut libc::c_void,
        buf_len: isize,
    ) -> (Poll<Result<(), Error>>, usize) {
        let mut blocked = s2n_blocked_status::NOT_BLOCKED;
        let mut read: isize = 0;
        let r = self.poll_negotiate_method(|conn| {
            unsafe {
                s2n_renegotiate(
                    conn.as_ptr(),
                    buf_ptr as *mut u8,
                    buf_len,
                    &mut read,
                    &mut blocked,
                )
            }
            .into_poll()
        });
        if let Ready(Ok(())) = r {
            self.renegotiate_state_mut().needs_handshake = false;
        }
        (r, read.try_into().unwrap())
    }

    /// Perform a new handshake on an already established connection.
    ///
    /// The first element of the returned pair represents progress on the new
    /// handshake, like [Connection::poll_negotiate()].
    ///
    /// If any application data is received during the new handshake, the number
    /// of bytes received is returned as the second element of the returned pair,
    /// and the data is written to `buf`.
    ///
    /// See s2n_renegotiate in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/renegotiate.h).
    pub fn poll_renegotiate(&mut self, buf: &mut [u8]) -> (Poll<Result<(), Error>>, usize) {
        let buf_len: isize = buf.len().try_into().unwrap_or(0);
        let buf_ptr = buf.as_ptr() as *mut ::libc::c_void;
        self.poll_renegotiate_raw(buf_ptr, buf_len)
    }

    /// Encrypts and sends data on a connection where
    /// [negotiate](`Self::poll_negotiate`) has succeeded.
    ///
    /// Returns the number of bytes written, and may indicate a partial write.
    pub fn poll_send(&mut self, buf: &[u8]) -> Poll<Result<usize, Error>> {
        if self.is_renegotiating() {
            return Ready(Err(Error::bindings(
                ErrorType::Blocked,
                "RenegotiateError",
                "Cannot send application data while renegotiating",
            )));
        }
        let mut blocked = s2n_blocked_status::NOT_BLOCKED;
        let buf_len: isize = buf.len().try_into().map_err(|_| Error::INVALID_INPUT)?;
        let buf_ptr = buf.as_ptr() as *const libc::c_void;
        let result = unsafe { s2n_send(self.as_ptr(), buf_ptr, buf_len, &mut blocked) }.into_poll();
        self.renegotiate_state_mut().send_pending = result.is_pending();
        result
    }

    pub(crate) fn poll_recv_raw(
        &mut self,
        buf_ptr: *mut libc::c_void,
        buf_len: isize,
    ) -> Poll<Result<usize, Error>> {
        if !self.is_renegotiating() {
            let mut blocked = s2n_blocked_status::NOT_BLOCKED;
            let result =
                unsafe { s2n_recv(self.as_ptr(), buf_ptr, buf_len, &mut blocked).into_poll() };
            // A call to s2n_recv that initiates renegotiation is blocked on
            // renegotiation, not on application data.
            // If we just return Pending, we may never start the handshake so
            // may never receive any more data from the server.
            // Instead, attempt to renegotiate at least once.
            return if self.is_renegotiating() && result.is_pending() {
                // We call poll_recv_raw instead of poll_renegotiate because we
                // could theoretically complete the entire handshake and read the
                // application data originally requested.
                // This also makes ensuring the wipe easier.
                self.poll_recv_raw(buf_ptr, buf_len)
            } else {
                result
            };
        }

        // Check to see if we need to drain any application bytes before
        // kicking off the renegotiation
        if self.peek_len() > 0 {
            let buf_len = std::cmp::min(self.peek_len() as isize, buf_len);
            let mut blocked = s2n_blocked_status::NOT_BLOCKED;
            return unsafe { s2n_recv(self.as_ptr(), buf_ptr, buf_len, &mut blocked).into_poll() };
        }

        // Wipe if starting renegotiation
        if self.renegotiate_state().needs_wipe {
            self.wipe_for_renegotiate()?;
        }

        match self.poll_renegotiate_raw(buf_ptr, buf_len) {
            (Ready(Err(err)), _) => Ready(Err(err)),
            // If renegotiate succeeds with no data read, we need to return
            // some result:
            // - We can't return Ready(Ok(0)), because that would indicate
            //   end-of-stream.
            // - We can't return Pending, because we are not actually blocked
            //   on anything so there would be no guarantee of another poll.
            // Instead, re-attempt to perform the original receive call
            // and return that result.
            (Ready(Ok(())), 0) => self.poll_recv_raw(buf_ptr, buf_len),
            (Pending, 0) => Pending,
            (_, bytes) => Ready(Ok(bytes)),
        }
    }
}

impl config::Builder {
    /// Sets a method to be called when the client receives a request to renegotiate.
    ///
    /// See s2n_config_set_renegotiate_request_cb in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/renegotiate.h).
    pub fn set_renegotiate_callback<T: 'static + RenegotiateCallback>(
        &mut self,
        handler: T,
    ) -> Result<&mut Self, Error> {
        unsafe extern "C" fn renegotiate_cb(
            conn_ptr: *mut s2n_connection,
            _context: *mut libc::c_void,
            response: *mut s2n_renegotiate_response::Type,
        ) -> libc::c_int {
            with_context(conn_ptr, |conn, context| {
                let callback = context.renegotiate.as_mut();
                if let Some(callback) = callback {
                    if let Some(result) = callback.on_renegotiate_request(conn) {
                        // If the callback indicates renegotiation, schedule it.
                        // This doesn't actually do any work related to renegotiation,
                        // It just indicates that work needs to be done later.
                        if result == RenegotiateResponse::Schedule {
                            conn.schedule_renegotiate();
                        }
                        *response = result.into();
                        return CallbackResult::Success.into();
                    }
                }
                CallbackResult::Failure.into()
            })
        }

        let handler = Box::new(handler);
        let context = self.context_mut();
        context.renegotiate = Some(handler);
        unsafe {
            s2n_config_set_renegotiate_request_cb(
                self.as_mut_ptr(),
                Some(renegotiate_cb),
                std::ptr::null_mut(),
            )
            .into_result()?;
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        callbacks::{
            ConnectionFuture, ConnectionFutureResult, PrivateKeyCallback, PrivateKeyOperation,
        },
        config::ConnectionInitializer,
        error::{ErrorSource, ErrorType},
        testing::{CertKeyPair, InsecureAcceptAllCertificatesHandler, TestPair, TestPairIO},
    };
    use foreign_types::ForeignTypeRef;
    use futures_test::task::new_count_waker;
    use openssl::ssl::{
        ErrorCode, Ssl, SslContext, SslFiletype, SslMethod, SslStream, SslVerifyMode, SslVersion,
    };
    use std::{
        error::Error,
        io::{Read, Write},
        pin::Pin,
        task::Poll::{Pending, Ready},
    };

    // The partial word is intentional to match variations:
    // "renegotiate", "renegotiating", "renegotiation"
    const RENEG_ERR_MARKER: &str = "renegotiat";

    // Currently renegotiation is not available from the openssl-sys bindings
    extern "C" {
        fn SSL_renegotiate(s: *mut openssl_sys::SSL) -> libc::size_t;
        fn SSL_renegotiate_pending(s: *mut openssl_sys::SSL) -> libc::size_t;
        fn SSL_in_init(s: *mut openssl_sys::SSL) -> libc::size_t;
    }

    // std::task::ready is unstable
    fn unwrap_poll<T>(
        poll: Poll<Result<T, crate::error::Error>>,
    ) -> Result<T, crate::error::Error> {
        if let Ready(value) = poll {
            return value;
        }
        panic!("Poll not Ready");
    }

    #[derive(Debug)]
    struct ServerTestStream(TestPairIO);

    // For server testing purposes, we read from the client output stream
    impl Read for ServerTestStream {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
            let result = self.0.client_tx_stream.borrow_mut().read(buf);
            if let Ok(0) = result {
                // Treat no data as blocking instead of EOF
                Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "blocking",
                ))
            } else {
                result
            }
        }
    }

    // For server testing purposes, we write to the server output stream
    impl Write for ServerTestStream {
        fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
            self.0.server_tx_stream.borrow_mut().write(buf)
        }

        fn flush(&mut self) -> Result<(), std::io::Error> {
            self.0.server_tx_stream.borrow_mut().flush()
        }
    }

    // s2n-tls doesn't support sending client hello requests.
    // This makes it impossible to test renegotiation without direct access to
    // s2n-tls internals like the methods for sending arbitrary records.
    // Instead, we need to use openssl as our server.
    //
    // The openssl SslStream::new method requires an owned Stream,
    // so the openssl server owns the TestPairIO. This is possible because the
    // s2n-tls client only references the TestPairIO via C callbacks.
    struct RenegotiateTestPair {
        client: Connection,
        server: SslStream<ServerTestStream>,
    }

    impl RenegotiateTestPair {
        fn from(mut builder: config::Builder) -> Result<Self, Box<dyn Error>> {
            // openssl and s2n-tls must be configured to accept each other's
            // certificates. Some tests will require client auth.
            //
            // openssl also requires a properly configured CA cert, which the
            // default TestPair does not include.
            let certs = CertKeyPair::from_path(
                "permutations/rsae_pkcs_4096_sha384/",
                "server-chain",
                "server-key",
                "ca-cert",
            );

            // Build the s2n-tls client.
            builder.load_pem(certs.cert(), certs.key())?;
            builder.trust_pem(certs.cert())?;
            builder.set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;
            let config = builder.build()?;
            let s2n_pair = TestPair::from_config(&config);
            let client = s2n_pair.client;

            // Build the openssl server.
            let mut ctx_builder = SslContext::builder(SslMethod::tls_server())?;
            ctx_builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
            ctx_builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
            ctx_builder.set_certificate_chain_file(certs.cert_path())?;
            ctx_builder.set_private_key_file(certs.key_path(), SslFiletype::PEM)?;
            ctx_builder.set_ca_file(certs.ca_path())?;
            ctx_builder.set_verify(SslVerifyMode::PEER);
            let openssl_ctx = ctx_builder.build();
            let openssl_ssl = Ssl::new(&openssl_ctx)?;

            // Connect the openssl server to the same IO that the s2n-tls
            // client was constructed to use.
            let server_stream = ServerTestStream(s2n_pair.io);
            let server = SslStream::new(openssl_ssl, server_stream)?;

            Ok(Self { client, server })
        }

        // Translate the output of openssl's `accept` to match s2n-tls's `poll_negotiate`.
        fn poll_openssl_negotiate(
            server: &mut SslStream<ServerTestStream>,
        ) -> Poll<Result<(), Box<dyn Error>>> {
            match server.accept() {
                Ok(_) => Ready(Ok(())),
                Err(err) if err.code() == ErrorCode::WANT_READ => Pending,
                Err(err) => Ready(Err(err.into())),
            }
        }

        // Perform a handshake with the s2n-tls client and openssl server
        fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
            loop {
                match (
                    self.client.poll_negotiate(),
                    Self::poll_openssl_negotiate(&mut self.server),
                ) {
                    (Poll::Ready(Ok(_)), Poll::Ready(Ok(_))) => return Ok(()),
                    // Error on the server
                    (_, Poll::Ready(Err(e))) => return Err(e),
                    // Error on the client
                    (Poll::Ready(Err(e)), _) => return Err(Box::new(e)),
                    _ => continue,
                }
            }
        }

        fn send_renegotiate_request(&mut self) -> Result<(), crate::error::Error> {
            let openssl_ptr = self.server.ssl().as_ptr();

            // Sanity check that renegotiation is not initially scheduled
            let requested = unsafe { SSL_renegotiate_pending(openssl_ptr) };
            assert_eq!(requested, 0, "Renegotiation should not be pending");

            // Schedule renegotiation
            unsafe { SSL_renegotiate(openssl_ptr) };

            // Verify that openssl scheduled the renegotiation
            let requested = unsafe { SSL_renegotiate_pending(openssl_ptr) };
            assert_eq!(requested, 1, "Renegotiation should be pending");

            // SSL_renegotiate doesn't actually send the message.
            // Like s2n-tls, a call to send / write is required.
            assert_eq!(
                self.server
                    .write(&[0; 0])
                    .expect("Failed to write hello request"),
                0
            );

            Ok(())
        }

        // Send and receive application data.
        // We have to ensure that application data continues to work during / after
        // the renegotiate.
        fn send_and_receive(&mut self) -> Result<(), Box<dyn Error>> {
            let to_send = [0; 1];
            let mut recv_buffer = [0; 1];
            self.server.write_all(&to_send)?;
            unwrap_poll(self.client.poll_recv(&mut recv_buffer))?;
            unwrap_poll(self.client.poll_send(&to_send))?;
            self.server.read_exact(&mut recv_buffer)?;
            Ok(())
        }

        // This indicates that openssl is performing a handshake, but not
        // specifically a renegotiation handshake. Ensure that the initial
        // handshake is complete before assuming that this indicates renegotiation.
        fn openssl_is_handshaking(&self) -> bool {
            (unsafe { SSL_in_init(self.server.ssl().as_ptr()) } == 1)
        }

        // The client drives renegotiation via poll_recv in order to read
        // application data written by the server after the new handshake.
        fn assert_renegotiate(&mut self) -> Result<(), Box<dyn Error>> {
            const APP_DATA: &[u8] = b"Renegotiation complete";
            let mut buffer = [0; APP_DATA.len()];

            for _ in 0..20 {
                let client_read_poll = self.client.poll_recv(&mut buffer);
                match client_read_poll {
                    Pending => {
                        assert!(self.client.is_renegotiating(), "s2n-tls not renegotiating");
                    }
                    Ready(Ok(bytes_read)) => {
                        assert_eq!(bytes_read, APP_DATA.len());
                        assert_eq!(&buffer, APP_DATA);
                        break;
                    }
                    Ready(err) => err.map(|_| ())?,
                };

                // Openssl needs to read the new ClientHello in order to know
                // that s2n-tls is actually renegotiating.
                // But after the initial read, writes can progress the handshake.
                if !self.openssl_is_handshaking() {
                    let _ = self.server.read(&mut [0; 0]);
                } else {
                    let server_write_result = self.server.write(APP_DATA);
                    println!(
                        "openssl result: {:?}, state: {:?}",
                        server_write_result,
                        self.server.ssl().state_string_long()
                    );
                    match server_write_result {
                        Ok(bytes_written) => assert_eq!(bytes_written, APP_DATA.len()),
                        Err(_) => {
                            assert!(self.openssl_is_handshaking(), "openssl not renegotiating");
                        }
                    }
                }
            }

            assert!(
                !self.client.is_renegotiating(),
                "s2n-tls renegotiation not complete"
            );
            assert!(
                !self.openssl_is_handshaking(),
                "openssl renegotiation not complete"
            );
            Ok(())
        }
    }

    #[test]
    fn ignore_callback() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Ignore)?;
        let mut pair = RenegotiateTestPair::from(builder)?;

        pair.handshake().expect("Initial handshake");

        // Expect receiving the hello request to be successful
        pair.send_renegotiate_request()
            .expect("Server sends request");
        pair.send_and_receive().expect("Application data");
        assert!(!pair.client.is_renegotiating(), "Unexpected renegotiation");

        Ok(())
    }

    // In practice, "accept" behaves just like "ignore".
    // The only current difference is application intention.
    #[test]
    fn accept_callback() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Accept)?;
        let mut pair = RenegotiateTestPair::from(builder)?;

        pair.handshake().expect("Initial handshake");

        // Expect receiving the hello request to be successful
        pair.send_renegotiate_request()
            .expect("Server sends request");
        pair.send_and_receive().expect("Application data");
        assert!(!pair.client.is_renegotiating(), "Unexpected renegotiation");

        Ok(())
    }

    #[test]
    fn error_callback() -> Result<(), Box<dyn Error>> {
        struct ErrorRenegotiateCallback {}
        impl RenegotiateCallback for ErrorRenegotiateCallback {
            fn on_renegotiate_request(
                &mut self,
                _: &mut Connection,
            ) -> Option<RenegotiateResponse> {
                None
            }
        }

        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(ErrorRenegotiateCallback {})?;
        let mut pair = RenegotiateTestPair::from(builder)?;

        pair.handshake().expect("Initial handshake");
        pair.send_renegotiate_request()
            .expect("Server sends request");
        // Expect receiving the hello request to be an error
        let error = unwrap_poll(pair.client.poll_recv(&mut [0; 1])).unwrap_err();
        assert_eq!(error.name(), "S2N_ERR_CANCELLED");

        Ok(())
    }

    #[test]
    fn reject_callback() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Reject)?;
        let mut pair = RenegotiateTestPair::from(builder)?;

        pair.handshake().expect("Initial handshake");
        pair.send_renegotiate_request()
            .expect("Server sends request");
        // s2n-tls doesn't fail when it rejects renegotiatation, it just sends
        // a warning alert. The peer chooses how to handle that alert.
        // The openssl server receives the alert on its next read.
        // Openssl considers the alert an error.
        let openssl_error = pair.send_and_receive().unwrap_err();
        assert!(openssl_error.to_string().contains("no renegotiation"));

        Ok(())
    }

    #[test]
    fn scheduled_renegotiate_basic() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Schedule)?;
        let mut pair = RenegotiateTestPair::from(builder)?;

        pair.handshake().expect("Initial handshake");
        pair.send_and_receive()
            .expect("Application data before renegotiate");
        pair.send_renegotiate_request()
            .expect("Server sends request");
        pair.assert_renegotiate().expect("Renegotiate");
        pair.send_and_receive()
            .expect("Application data after renegotiate");

        Ok(())
    }

    #[test]
    fn scheduled_renegotiate_repeatedly() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Schedule)?;
        let mut pair = RenegotiateTestPair::from(builder)?;

        pair.handshake().expect("Initial handshake");

        for _ in 0..10 {
            pair.send_and_receive()
                .expect("Application data before renegotiate");
            pair.send_renegotiate_request()
                .expect("Server sends request");
            pair.assert_renegotiate().expect("Renegotiate");
            pair.send_and_receive()
                .expect("Application data after renegotiate");
        }

        Ok(())
    }

    // Application data received immediately after the hello request message
    // is handled by the initial s2n_recv call rather than s2n_renegotiate
    #[test]
    fn scheduled_renegotiate_with_immediate_app_data() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Schedule)?;
        let mut pair = RenegotiateTestPair::from(builder)?;
        pair.handshake().expect("Initial handshake");

        // Server sends app data immediately after hello request
        let server_data = b"server_data";
        pair.send_renegotiate_request()
            .expect("server hello request");
        pair.server
            .write_all(server_data)
            .expect("server app data after hello request");

        // First poll reads both the hello request and the app data
        let mut buffer = [0; 100];
        let read = unwrap_poll(pair.client.poll_recv(&mut buffer))?;
        assert_eq!(read, server_data.len());
        assert_eq!(&buffer[0..read], server_data);
        assert!(pair.client.is_renegotiating());

        pair.assert_renegotiate().expect("Renegotiate");
        Ok(())
    }

    // Application data received some time after the hello request is handled
    // by s2n_renegotiate rather than s2n_recv.
    #[test]
    fn scheduled_renegotiate_with_delayed_app_data() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Schedule)?;
        let mut pair = RenegotiateTestPair::from(builder)?;
        pair.handshake().expect("Initial handshake");

        // Server sends hello request, but initially no app data
        pair.send_renegotiate_request()
            .expect("server hello request");

        // Client can read the hello request
        let mut buffer = [0; 100];
        let poll = pair.client.poll_recv(&mut buffer);
        assert!(poll.is_pending());
        assert!(pair.client.is_renegotiating());

        // Server sends app data
        let server_data = b"server_data";
        pair.server
            .write_all(server_data)
            .expect("server app data after hello request");

        // Client reads app data
        let mut buffer = [0; 100];
        let read = unwrap_poll(pair.client.poll_recv(&mut buffer))?;
        assert_eq!(read, server_data.len());
        assert_eq!(&buffer[0..read], server_data);
        assert!(pair.client.is_renegotiating());

        pair.assert_renegotiate().expect("Renegotiate");
        Ok(())
    }

    // assert_renegotiate sends application data for the client to receive
    // as soon as the handshake completes. Also test with no final application data.
    #[test]
    fn scheduled_renegotiate_without_final_app_data() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Schedule)?;
        let mut pair = RenegotiateTestPair::from(builder)?;
        pair.handshake().expect("Initial handshake");

        // Server sends hello request, but initially no app data
        pair.send_renegotiate_request()
            .expect("server hello request");

        // Client and server renegotiate while never reading app data
        assert!(pair.client.poll_recv(&mut [0; 1]).is_pending());
        assert!(pair.client.is_renegotiating());
        loop {
            let _ = pair.server.read(&mut [0; 0]);
            assert!(pair.client.poll_recv(&mut [0; 1]).is_pending());
            if !pair.client.is_renegotiating() {
                break;
            }
        }

        // Send and receive application data after renegotiation
        pair.send_and_receive()
            .expect("Application data after renegotiate");

        Ok(())
    }

    // Renegotiation should be able to clear buffered receive data before wiping
    #[test]
    fn scheduled_renegotiate_with_buffered_recv() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Schedule)?;
        let mut pair = RenegotiateTestPair::from(builder)?;
        pair.handshake().expect("Initial handshake");

        pair.send_renegotiate_request()
            .expect("Server sends request");
        let server_data = b"server_data";
        assert_eq!(
            pair.server.write(server_data).expect("server app data"),
            server_data.len()
        );

        // Read only the first byte of the server data
        let mut buffer = [0; 100];
        let read = unwrap_poll(pair.client.poll_recv(&mut buffer[..1]))
            .expect("Read first byte of server data");
        assert_eq!(read, 1);
        assert_eq!(buffer[0], server_data[0]);
        assert!(pair.client.is_renegotiating());

        // Read the rest of the server data
        let read = unwrap_poll(pair.client.poll_recv(&mut buffer[1..]))
            .expect("Drain buffered receive data");
        assert_eq!(read, server_data.len() - 1);
        assert_eq!(&buffer[..server_data.len()], server_data);
        assert!(pair.client.is_renegotiating());

        pair.assert_renegotiate().expect("Renegotiate");
        Ok(())
    }

    // Renegotiation will fail if there is a pending call to poll_send
    #[test]
    fn scheduled_renegotiate_with_buffered_send() -> Result<(), Box<dyn Error>> {
        unsafe extern "C" fn blocking_send_cb(
            _: *mut libc::c_void,
            _: *const u8,
            _: u32,
        ) -> libc::c_int {
            errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
            -1
        }

        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Schedule)?;
        let mut pair = RenegotiateTestPair::from(builder)?;
        pair.handshake().expect("Initial handshake");

        // The client needs to initially block on send.
        let client_data = b"client data";
        pair.client.set_send_callback(Some(blocking_send_cb))?;
        assert!(pair.client.poll_send(client_data).is_pending());
        assert!(pair.client.renegotiate_state().send_pending);

        // The client fails to start renegotiation due to pending send.
        pair.send_renegotiate_request()
            .expect("Server sends request");
        let error = unwrap_poll(pair.client.poll_recv(&mut [0; 1])).unwrap_err();
        assert_eq!(error.kind(), ErrorType::UsageError);
        assert!(error.message().contains(RENEG_ERR_MARKER));
        assert!(error.message().contains("buffered send data"));
        assert!(pair.client.is_renegotiating());

        Ok(())
    }

    // poll_send is not currently supported during renegotiation
    #[test]
    fn scheduled_renegotiate_with_poll_send() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Schedule)?;
        let mut pair = RenegotiateTestPair::from(builder)?;
        pair.handshake().expect("Initial handshake");

        // Read the hello request and start renegotiation
        pair.send_renegotiate_request()
            .expect("server HELLO_REQUEST");
        assert!(pair.client.poll_recv(&mut [0; 1]).is_pending());
        assert!(pair.client.is_renegotiating());

        // Calls to poll_send now fail
        let error = unwrap_poll(pair.client.poll_send(&[0; 1])).unwrap_err();
        assert_eq!(error.kind(), ErrorType::Blocked);
        assert!(error.message().contains(RENEG_ERR_MARKER));
        assert!(error.message().contains("send application data"));
        assert!(pair.client.is_renegotiating());

        Ok(())
    }

    #[test]
    fn scheduled_renegotiate_with_async_callback() -> Result<(), Box<dyn Error>> {
        // To test how renegotiate handles blocking on async callbacks,
        // we need an async callback that triggers on the client.
        // Currently our only option is the async pkey callback.
        struct TestAsyncCallback {
            count: usize,
            op: Option<PrivateKeyOperation>,
        }
        impl PrivateKeyCallback for TestAsyncCallback {
            fn handle_operation(
                &self,
                _: &mut Connection,
                operation: PrivateKeyOperation,
            ) -> ConnectionFutureResult {
                Ok(Some(Box::pin(TestAsyncCallback {
                    count: self.count,
                    op: Some(operation),
                })))
            }
        }
        impl ConnectionFuture for TestAsyncCallback {
            fn poll(
                self: Pin<&mut Self>,
                conn: &mut Connection,
                ctx: &mut core::task::Context,
            ) -> Poll<Result<(), crate::error::Error>> {
                ctx.waker().wake_by_ref();
                let this = self.get_mut();
                if this.count > 1 {
                    // Repeatedly block the handshake in order to verify
                    // that renegotiate can handle Pending callbacks.
                    this.count -= 1;
                    Pending
                } else {
                    // Perform the pkey operation with the selected cert / key pair.
                    let op = this.op.take().unwrap();
                    let opt_ptr = op.as_ptr();
                    let chain_ptr = conn.selected_cert().unwrap().as_ptr();
                    unsafe {
                        // SAFETY, mut cast: get_private_key does not modify the
                        // chain, and it is invalid to modify key through `key_ptr`
                        let key_ptr = s2n_cert_chain_and_key_get_private_key(chain_ptr as *mut _)
                            .into_result()?
                            .as_ptr();
                        s2n_async_pkey_op_perform(opt_ptr, key_ptr).into_result()?;
                        s2n_async_pkey_op_apply(opt_ptr, conn.as_ptr()).into_result()?;
                    }
                    Ready(Ok(()))
                }
            }
        }

        let count_per_handshake = 10;
        let async_callback = TestAsyncCallback {
            count: count_per_handshake,
            op: None,
        };

        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Schedule)?;
        builder.set_private_key_callback(async_callback)?;
        let mut pair = RenegotiateTestPair::from(builder)?;

        let (waker, wake_count) = new_count_waker();
        pair.client.set_waker(Some(&waker))?;

        pair.handshake().expect("Initial handshake");
        assert_eq!(wake_count, count_per_handshake);
        pair.send_renegotiate_request()
            .expect("Server sends request");
        pair.assert_renegotiate()?;

        assert_eq!(wake_count, count_per_handshake * 2);
        Ok(())
    }

    #[test]
    fn scheduled_renegotiate_with_async_init() -> Result<(), Box<dyn Error>> {
        // To test that the initializer method triggers again on the second
        // handshake, we need to set an easily verified connection-level value.
        #[derive(Clone)]
        struct TestInitializer {
            count: usize,
            context: String,
        }
        impl ConnectionInitializer for TestInitializer {
            fn initialize_connection(
                &self,
                _: &mut crate::connection::Connection,
            ) -> ConnectionFutureResult {
                Ok(Some(Box::pin(self.clone())))
            }
        }
        impl ConnectionFuture for TestInitializer {
            fn poll(
                self: Pin<&mut Self>,
                conn: &mut Connection,
                ctx: &mut core::task::Context,
            ) -> Poll<Result<(), crate::error::Error>> {
                ctx.waker().wake_by_ref();
                let this = self.get_mut();
                // Assert that nothing is currently set
                assert!(conn.application_context::<String>().is_none());
                if this.count > 1 {
                    // Repeatedly block the handshake in order to verify
                    // that renegotiate can handle Pending callbacks.
                    this.count -= 1;
                    Pending
                } else {
                    conn.set_application_context(this.context.clone());
                    Ready(Ok(()))
                }
            }
        }

        let count_per_handshake = 10;
        let expected_context = "helloworld".to_owned();
        let initializer = TestInitializer {
            count: count_per_handshake,
            context: expected_context.clone(),
        };

        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Schedule)?;
        builder.set_connection_initializer(initializer)?;
        let mut pair = RenegotiateTestPair::from(builder)?;

        let (waker, wake_count) = new_count_waker();
        pair.client.set_waker(Some(&waker))?;

        pair.handshake().expect("Initial handshake");
        assert_eq!(wake_count, count_per_handshake);
        pair.send_renegotiate_request()
            .expect("Server sends request");
        pair.assert_renegotiate()?;
        assert_eq!(wake_count, count_per_handshake * 2);

        let context: Option<&String> = pair.client.application_context();
        assert_eq!(Some(&expected_context), context);

        Ok(())
    }

    #[test]
    fn wipe_for_renegotiate_failure() -> Result<(), Box<dyn Error>> {
        let mut connection = Connection::new_server();
        // Servers can't renegotiate
        let error = connection.wipe_for_renegotiate().unwrap_err();
        assert_eq!(error.source(), ErrorSource::Library);
        assert_eq!(error.name(), "S2N_ERR_NO_RENEGOTIATION");
        Ok(())
    }
}
