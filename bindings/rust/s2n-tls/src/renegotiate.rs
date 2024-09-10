// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Methods to perform renegotiation.
//!
//! The use of renegotiation is strongly discouraged.
//! See [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/renegotiate.h).
//!
//! Unlike the C API, the Rust bindings do not require the application to
//! integrate s2n_renegotiate_wipe or s2n_renegotiate into their existing code.
//! Instead, all that is required to enable renegotiation is setting the RenegotiateCallback.
//!
//! For example:
//! ```
//! use s2n_tls::config::Builder;
//! use s2n_tls::connection::Connection;
//! use s2n_tls::error::Error;
//! use s2n_tls::renegotiate::{RenegotiateCallback, RenegotiateResponse};
//!
//! #[derive(Default)]
//! struct Callback { };
//!
//! impl RenegotiateCallback for Callback {
//!     fn on_renegotiate_request(
//!         &mut self,
//!         conn: &mut Connection,
//!     ) -> Option<RenegotiateResponse> {
//!         let response = match conn.server_name() {
//!             Some("allowed_to_renegotiate") => RenegotiateResponse::Accept,
//!             _ => RenegotiateResponse::Reject,
//!         };
//!         Some(response)
//!     }
//!
//!     fn on_renegotiate_wipe(&mut self, conn: &mut Connection) -> Result<(), Error> {
//!         conn.set_server_name("not_allowed_to_renegotiate")?;
//!         Ok(())
//!     }
//! }
//!
//! let mut builder = Builder::new();
//! builder.set_renegotiate_callback(Callback::default());
//! ```
//!
//! If all renegotiation requests will be accepted and no connection-level
//! configuration is required, then RenegotiateResponse can be used as the RenegotiateCallback.
//! However, be careful: using any async callback requires connection-level configuration
//! due to [Connection::set_waker()].
//!
//! For example:
//! ```
//! use s2n_tls::config::Builder;
//! use s2n_tls::renegotiate::RenegotiateResponse;
//!
//! let mut builder = Builder::new();
//! builder.set_renegotiate_callback(RenegotiateResponse::Accept);
//! ```
//!
//! When an s2n-tls client receives a renegotiation request, `on_renegotiate_request`
//! will be invoked. If `on_renegotiate_request` returns `RenegotiateResponse::Accept`,
//! then s2n-tls will automatically schedule renegotiation. The application will
//! be able to complete any in-progress writes and read any already decrypted
//! data. However, the next time that a read or write would trigger reading or
//! writing a new TLS record, s2n-tls will instead wipe the connection, block
//! all application IO requests, and negotiate a new handshake. Both `poll_recv`
//! and `poll_send` will return Pending until renegotiation is complete.
//!
//! Handling renegotiation this way allows it to be used with higher level abstractions
//! that are unaware of renegotiation, like s2n-tls-tokio or s2n-tls-hyper.
//! However, there are downsides. During renegotiation, `poll_recv` may write and
//! `poll_send` may read. This may pose a problem if we eventually implement a
//! proper "split" operation. It also makes waker contracts difficult to reason about,
//! so any integration should probably include as much testing and instrumentation
//! as possible. Please report any bugs encountered.
//! ```

use s2n_tls_sys::*;

use crate::{
    callbacks::with_context,
    config,
    connection::Connection,
    enums::CallbackResult,
    error::{Error, Fallible, Pollable},
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
}

impl From<RenegotiateResponse> for s2n_renegotiate_response::Type {
    fn from(input: RenegotiateResponse) -> s2n_renegotiate_response::Type {
        match input {
            RenegotiateResponse::Ignore => s2n_renegotiate_response::RENEGOTIATE_IGNORE,
            RenegotiateResponse::Reject => s2n_renegotiate_response::RENEGOTIATE_REJECT,
            RenegotiateResponse::Accept => s2n_renegotiate_response::RENEGOTIATE_ACCEPT,
        }
    }
}

/// Callbacks related to the renegotiation TLS feature.
pub trait RenegotiateCallback: 'static + Send + Sync {
    /// A callback that triggers when the client receives a renegotiation request
    /// (a HelloRequest message) from the server.
    ///
    /// Returning `Some(RenegotiateResponse::Accept)` will trigger s2n-tls
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
    /// configuration like the server name will need to be set again via this callback.
    ///
    /// See s2n_renegotiate_wipe in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/renegotiate.h).
    /// The Rust equivalent of the listed connection-specific methods that are NOT wiped are:
    ///  - Methods to set the file descriptors: not currently supported by rust bindings
    ///  - Methods to set the send callback:
    ///    ([Connection::set_send_callback()], [Connection::set_send_context()])
    ///  - Methods to set the recv callback:
    ///    ([Connection::set_receive_callback()], [Connection::set_receive_context()])
    ///
    /// Wakers set via [Connection::set_waker()] count as connection-level configuration
    /// and must be set again.
    ///
    /// If this callback returns `Err`, then renegotiation will fail with a fatal error.
    fn on_renegotiate_wipe(&mut self, _connection: &mut Connection) -> Result<(), Error> {
        Ok(())
    }
}

impl RenegotiateCallback for RenegotiateResponse {
    fn on_renegotiate_request(&mut self, _conn: &mut Connection) -> Option<RenegotiateResponse> {
        Some(*self)
    }
}

#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub(crate) struct RenegotiateState {
    need_wipe: bool,
    need_handshake: bool,
    send_blocked: bool,
}

impl RenegotiateState {
    fn set_renegotiate(&mut self) {
        // Requests for renegotiation should be ignored if a renegotiation is already in progress.
        if !self.need_handshake {
            self.need_wipe = true;
            self.need_handshake = true;
        }
    }
}

impl Connection {
    fn accept_renegotiate_request(&mut self) {
        self.renegotiate_state_mut().set_renegotiate();
    }

    fn is_renegotiating(&self) -> bool {
        self.renegotiate_state().need_handshake
    }

    /// Reset the connection so that it can be renegotiated.
    ///
    /// See s2n_renegotiate_wipe in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/renegotiate.h).
    fn wipe_for_renegotiate(&mut self) -> Result<(), Error> {
        let renegotiate_state = *self.renegotiate_state();
        self.wipe_method(|conn| unsafe { s2n_renegotiate_wipe(conn.as_ptr()).into_result() })?;
        *self.renegotiate_state_mut() = renegotiate_state;
        if let Some(mut config) = self.config() {
            if let Some(callback) = config.context_mut().renegotiate.as_mut() {
                callback.on_renegotiate_wipe(self)?;
            }
        }
        Ok(())
    }

    /// Make progress on the renegotiation handshake.
    ///
    /// This method matches the interface of `poll_recv`, and as such does not
    /// actually indicate whether the handshake completes or not. It returns
    /// `Ready` when application data is available, not when the handshake succeeds.
    ///
    /// If the handshake succeeds, the renegotiation state stored on the connection
    /// will be updated so that this method is not polled again.
    ///
    /// # Safety
    /// We have to worry about interleaved `poll_recv` and `poll_send` calls
    /// when managing state, but we do not have to worry about thread safety.
    /// Both `poll_recv` and `poll_send` take mut references, and Connection does
    /// not currently support a true "split" operation.
    fn poll_renegotiate_raw(
        &mut self,
        buf_ptr: *mut libc::c_void,
        buf_len: isize,
    ) -> Poll<Result<usize, Error>> {
        if self.renegotiate_state().need_wipe {
            if self.renegotiate_state().send_blocked || self.peek_len() > 0 {
                // It is safe to return Pending here because `poll_recv` and
                // `poll_send` are already responsible for clearing the input
                // and output buffers respectively. The first one to succeed
                // will block, but the second will wipe and begin renegotiation.
                return Pending;
            }
            self.wipe_for_renegotiate()?;
            self.renegotiate_state_mut().need_wipe = false;
        }

        let mut blocked = s2n_blocked_status::NOT_BLOCKED;
        let mut read: isize = 0;
        let result = self.poll_negotiate_method(|conn| {
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

        if result.is_ready() {
            self.renegotiate_state_mut().need_handshake = false
        }
        if read > 0 {
            return Ready(Ok(read.try_into().unwrap()));
        }
        match result {
            Ready(Ok(_)) => Pending,
            Ready(Err(err)) => Ready(Err(err)),
            Pending => Pending,
        }
    }

    fn poll_renegotiate(&mut self, buf: &mut [u8]) -> Poll<Result<usize, Error>> {
        let buf_len: isize = buf.len().try_into().map_err(|_| Error::INVALID_INPUT)?;
        let buf_ptr = buf.as_mut_ptr() as *mut libc::c_void;
        self.poll_renegotiate_raw(buf_ptr, buf_len)
    }

    /// Encrypts and sends data on a connection where
    /// [negotiate](`Self::poll_negotiate`) has succeeded.
    ///
    /// Returns the number of bytes written, and may indicate a partial write.
    ///
    /// Automatically handles renegotiation.
    pub fn poll_send(&mut self, buf: &[u8]) -> Poll<Result<usize, Error>> {
        let mut blocked = s2n_blocked_status::NOT_BLOCKED;
        let buf_len: isize = buf.len().try_into().map_err(|_| Error::INVALID_INPUT)?;
        let buf_ptr = buf.as_ptr() as *const libc::c_void;

        // If send is blocked, then we can't override poll_send to call
        // poll_renegotiate until the application finishes retrying the send.
        fn is_send_renegotiating(conn: &mut Connection) -> bool {
            conn.is_renegotiating() && !conn.renegotiate_state().send_blocked
        }

        let is_renegotiating = is_send_renegotiating(self);
        let result = if is_renegotiating {
            let mut empty = [0; 0];
            self.poll_renegotiate(&mut empty)
        } else {
            let result =
                unsafe { s2n_send(self.as_ptr(), buf_ptr, buf_len, &mut blocked) }.into_poll();
            // s2n-tls can't automatically flush blocked sends.
            // The application must call s2n_send again with the same data buffer
            // in order to retry a send.
            // Since we can't flush automatically, we need to track whether or
            // not send has been flushed by the application.
            self.renegotiate_state_mut().send_blocked = result.is_pending();
            result
        };

        // A call to poll_renegotiate can trigger the need to call s2n_send.
        // If the handshake blocking sending application data completes, then we
        // need to attempt to send the application data at least once before we
        // return Pending. Otherwise, we aren't actually blocked on anything
        // specific and could break an underlying IO waker contract.
        //
        // A call to s2n_send can not trigger the need to call poll_negotiate.
        // Even if it clears the last of the buffered data blocking renegotiation,
        // the result will always be `Ready(Ok(bytes_written))` rather than `Pending`.
        //
        // Despite only one case being possible, we follow the same pattern as
        // we do for poll_recv for consistency and simplicity.
        let is_next_renegotiating = is_send_renegotiating(self);
        if result.is_pending() && is_renegotiating != is_next_renegotiating {
            self.poll_send(buf)
        } else {
            result
        }
    }

    pub(crate) fn poll_recv_raw(
        &mut self,
        buf_ptr: *mut libc::c_void,
        buf_len: isize,
    ) -> Poll<Result<usize, Error>> {
        let mut blocked = s2n_blocked_status::NOT_BLOCKED;

        // Let s2n_recv handle draining any buffered IO.
        // We could let poll_negotiate handle it, but this way matches poll_send.
        fn is_recv_renegotiating(conn: &mut Connection) -> bool {
            conn.is_renegotiating() && conn.peek_len() == 0
        }

        // If we're just trying to drain the buffered IO,
        // ensure that we don't read more records.
        let buf_len = if self.is_renegotiating() && self.peek_len() > 0 {
            std::cmp::min(buf_len, self.peek_len() as isize)
        } else {
            buf_len
        };

        let is_renegotiating = is_recv_renegotiating(self);
        let result = if is_renegotiating {
            self.poll_renegotiate_raw(buf_ptr, buf_len)
        } else {
            unsafe { s2n_recv(self.as_ptr(), buf_ptr, buf_len, &mut blocked).into_poll() }
        };

        // A call to s2n_recv can trigger the need to call poll_negotiate if it
        // reads a HelloRequest but no ApplicationData. If we returned Pending in
        // that case without attempting to progress the handshake, we could break
        // an underlying IO waker contract; the operation wouldn't actually be blocked
        // on anything specific.
        //
        // A call to poll_negotiate can trigger the need to call s2n_recv if it
        // completes the handshake that is blocking receiving application data.
        // The server does write the final message in some TLS1.2 handshakes.
        // If we returned Pending in that case without attempting to read the
        // application data requested by the application, we would again be
        // at risk of breaking underlying IO waker contracts.
        let is_renegotiating_next = is_recv_renegotiating(self);
        if result.is_pending() && is_renegotiating != is_renegotiating_next {
            self.poll_recv_raw(buf_ptr, buf_len)
        } else {
            result
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
                        // It just indicates to `poll_recv` and `poll_send`
                        // that work needs to be done later.
                        if result == RenegotiateResponse::Accept {
                            conn.accept_renegotiate_request();
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
        error::ErrorSource,
        testing::{CertKeyPair, InsecureAcceptAllCertificatesHandler, TestPair, TestPairIO},
    };
    use foreign_types::ForeignTypeRef;
    use futures_test::task::new_count_waker;
    use openssl::ssl::{
        ErrorCode, NameType, Ssl, SslContext, SslFiletype, SslMethod, SslStream, SslVerifyMode,
        SslVersion,
    };
    use std::{
        error::Error,
        io::{Read, Write},
        pin::Pin,
        task::{
            Poll::{Pending, Ready},
            Waker,
        },
    };

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
            let certs_dir = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../tests/pems/permutations/rsae_pkcs_4096_sha384/"
            );
            let certs = CertKeyPair::from(certs_dir, "server-chain", "server-key", "ca-cert");

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
            self.server
                .write(&[0; 0])
                .expect("Failed to write hello request");

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
            const APP_DATA: &[u8] = "Renegotiation complete".as_bytes();
            let mut buffer = [0; APP_DATA.len()];

            for _ in 0..20 {
                let client_read_poll = self.client.poll_recv(&mut buffer);
                println!(
                    "s2n result: {:?}, state: {:?}",
                    client_read_poll,
                    self.client.message_type()?
                );
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
                // But after initial read, reads and writes can both progress the handshake.
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
    fn do_renegotiate_basic() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Accept)?;
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
    fn do_renegotiate_repeatedly() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Accept)?;
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

    #[test]
    fn do_renegotiate_with_app_data() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Accept)?;
        let mut pair = RenegotiateTestPair::from(builder)?;
        pair.handshake().expect("Initial handshake");

        // The server can send:
        // - APP_DATA
        // - HELLO_REQUEST
        // - APP_DATA
        // - SERVER_HELLO
        // No more application data is allowed until the handshake completes.
        let server_data_before_request = "server_data_before_request".as_bytes();
        pair.server
            .write(server_data_before_request)
            .expect("server APP_DATA before HELLO_REQUEST");
        pair.send_renegotiate_request()
            .expect("server HELLO_REQUEST");
        let server_data_before_hello = "server_data_before_hello".as_bytes();
        pair.server
            .write(server_data_before_hello)
            .expect("server APP_DATA before CLIENT_HELLO");
        let server_data = [server_data_before_request, server_data_before_hello];

        // The client can send:
        // - APP_DATA
        // - CLIENT_HELLO
        // No more application data is allowed until the handshake completes.
        let client_data_before_hello = "client_data_before_hello".as_bytes();
        unwrap_poll(pair.client.poll_send(client_data_before_hello))
            .expect("client APP_DATA before CLIENT_HELLO");

        // Client reads all server data
        for data in server_data {
            let mut buffer = [0; 100];
            let read = unwrap_poll(pair.client.poll_recv(&mut buffer))?;
            assert_eq!(read, data.len());
            assert_eq!(&buffer[0..read], data);
        }

        // Server reads all client data
        let mut buffer = [0; 100];
        let read = pair.server.read(&mut buffer)?;
        assert_eq!(read, client_data_before_hello.len());
        assert_eq!(&buffer[0..read], client_data_before_hello);

        // Assert that a renegotiation is in progress
        assert!(pair.client.is_renegotiating());
        // Complete the renegotiation
        pair.assert_renegotiate()?;
        Ok(())
    }

    #[test]
    fn do_renegotiate_with_buffered_read() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Accept)?;
        let mut pair = RenegotiateTestPair::from(builder)?;

        pair.handshake().expect("Initial handshake");

        let server_data = "full server data".as_bytes();
        pair.send_renegotiate_request()
            .expect("Server sends request");
        pair.server.write(&server_data)?;

        // Read the server data one byte at a time, slowly draining the buffered data.
        for i in 0..server_data.len() {
            // The renegotiation request is read with the first byte,
            // but wiping is blocked until all the buffered data is drained.
            assert_eq!(pair.client.is_renegotiating(), i > 0);
            assert_eq!(pair.client.renegotiate_state().need_wipe, i > 0);

            let mut buffer = [0; 1];
            let read = unwrap_poll(pair.client.poll_recv(&mut buffer))?;
            assert_eq!(read, 1);
            assert_eq!(buffer[0], server_data[i]);
            assert_eq!(pair.client.peek_len(), server_data.len() - i - 1);
        }

        pair.assert_renegotiate().expect("Renegotiate");
        Ok(())
    }

    #[test]
    fn do_renegotiate_with_buffered_write() -> Result<(), Box<dyn Error>> {
        unsafe extern "C" fn blocking_send_cb(
            _: *mut libc::c_void,
            _: *const u8,
            _: u32,
        ) -> libc::c_int {
            errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
            return -1;
        }

        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Accept)?;
        let mut pair = RenegotiateTestPair::from(builder)?;
        pair.handshake().expect("Initial handshake");

        // The client needs to initially block on send.
        let client_data = "client data".as_bytes();
        pair.client.set_send_callback(Some(blocking_send_cb))?;
        assert!(pair.client.poll_send(&client_data).is_pending());
        assert!(pair.client.renegotiate_state_mut().send_blocked);

        // Renegotiation should also initially block on send.
        pair.send_renegotiate_request()
            .expect("Server sends request");
        assert!(pair.client.poll_recv(&mut [0; 1]).is_pending());
        assert!(pair.client.poll_send(&client_data).is_pending());
        assert!(pair.client.is_renegotiating());
        assert!(pair.client.renegotiate_state_mut().send_blocked);

        // Unblock sending by restoring the original callback
        pair.client.set_send_callback(Some(TestPair::send_cb))?;
        unwrap_poll(pair.client.poll_send(&client_data)).expect("Send unblocked");
        assert!(!pair.client.renegotiate_state_mut().send_blocked);

        // Server can now receive the data.
        let mut buffer = [0; 100];
        let read = pair.server.read(&mut buffer).expect("Server read");
        assert_eq!(read, client_data.len());
        assert_eq!(&buffer[..read], client_data);

        pair.assert_renegotiate().expect("Renegotiate");
        Ok(())
    }

    #[test]
    fn do_renegotiate_via_send() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Accept)?;
        let mut pair = RenegotiateTestPair::from(builder)?;
        pair.handshake().expect("Initial handshake");

        // Initially renegotiation can only be triggered by poll_recv.
        // Setup the calls such that buffered data prevents renegotiation from
        // making any progress on the initial poll_recv (the wipe is blocked).
        let buffered_server_data = "buffered_server_data".as_bytes();
        pair.send_renegotiate_request()
            .expect("server HELLO_REQUEST");
        pair.server.write(&buffered_server_data)?;
        let read = unwrap_poll(pair.client.poll_recv(&mut [0; 1]))?;
        assert_eq!(read, 1);
        assert!(pair.client.is_renegotiating());
        // Buffered data blocks the wipe
        assert!(pair.client.peek_len() > 0);
        assert!(pair.client.renegotiate_state().need_wipe);

        // The server can continue to write application data.
        // This application data is not buffered before renegotiation,
        // and will need to be read during renegotiation.
        let server_data = "server_data".as_bytes();
        pair.server
            .write(server_data)
            .expect("server writes app data");

        // The server needs to call read in order to receive the ClientHello
        // and start renegotiation. This should send the ServerHello.
        pair.server
            .read(&mut [0; 1])
            .expect_err("server blocks on reading app data");

        // Assert that poll_send can't drain the buffered data so can't make
        // progress on renegotiation. poll_send has no mechanism for returning
        // the buffered data to the application.
        let client_data = "client_data".as_bytes();
        assert!(pair.client.poll_send(&client_data).is_pending());
        assert!(pair.client.peek_len() > 0);
        assert!(pair.client.renegotiate_state().need_wipe);

        // Drain the buffered data via poll_recv
        let mut buffer = [0; 100];
        let expected = pair.client.peek_len();
        let read = unwrap_poll(pair.client.poll_recv(&mut buffer))?;
        assert_eq!(read, expected);
        assert_eq!(pair.client.peek_len(), 0);
        assert!(pair.client.renegotiate_state().need_wipe);

        // Progress the handshake via poll_send.
        // However, renegotiation is blocked on the next application data
        // because poll_send has no mechansim for returning application data.
        assert!(pair.client.poll_send(&client_data).is_pending());
        // Renegotiation at least progressed past the wipe
        assert!(pair.client.is_renegotiating());
        assert!(!pair.client.renegotiate_state().need_wipe);

        // Let poll_recv handle the application data
        let mut buffer = [0; 100];
        let read = unwrap_poll(pair.client.poll_recv(&mut buffer))?;
        assert_eq!(read, server_data.len());
        assert_eq!(&buffer[..read], server_data);

        // Finish renegotiation with poll_send
        loop {
            // The s2n client should only send after completing the new handshake
            match pair.client.poll_send(&client_data) {
                Ready(Ok(sent)) => {
                    assert_eq!(sent, client_data.len());
                    assert!(!pair.client.is_renegotiating());
                    break;
                }
                Ready(err) => panic!("Renegotiate failed: {:?}", err),
                Pending => assert!(pair.client.is_renegotiating()),
            }
            let mut buffer = [0; 100];
            // The openssl server should always block on reading
            assert!(pair.server.read(&mut buffer).is_err());
        }

        // After renegotiation, the openssl server can read the sent data.
        let mut buffer = [0; 100];
        let read = pair.server.read(&mut buffer)?;
        assert_eq!(read, client_data.len());
        assert_eq!(&buffer[..read], client_data);

        Ok(())
    }

    #[derive(Debug, Clone)]
    struct WakerRenegotiateCallback(Waker);
    impl RenegotiateCallback for WakerRenegotiateCallback {
        fn on_renegotiate_request(&mut self, conn: &mut Connection) -> Option<RenegotiateResponse> {
            RenegotiateResponse::Accept.on_renegotiate_request(conn)
        }

        fn on_renegotiate_wipe(
            &mut self,
            conn: &mut Connection,
        ) -> Result<(), crate::error::Error> {
            conn.set_waker(Some(&self.0))?;
            Ok(())
        }
    }

    #[test]
    fn do_renegotiate_with_async_callback() -> Result<(), Box<dyn Error>> {
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
                    let chain_ptr = conn.selected_cert().unwrap().as_mut_ptr().as_ptr();
                    unsafe {
                        let key_ptr = s2n_cert_chain_and_key_get_private_key(chain_ptr)
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

        let (waker, wake_count) = new_count_waker();
        let reneg_callback = WakerRenegotiateCallback(waker.clone());

        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(reneg_callback)?;
        builder.set_private_key_callback(async_callback)?;
        let mut pair = RenegotiateTestPair::from(builder)?;
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
    fn do_renegotiate_with_async_init() -> Result<(), Box<dyn Error>> {
        // To test that the initializer method triggers again on the second
        // handshake, we need to set an easily verified connection-level value.
        // The server name is convenient.
        #[derive(Clone)]
        struct TestInitializer {
            count: usize,
            server_name: String,
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
                // Assert that the server name is not already set
                assert!(conn.server_name().is_none());
                if this.count > 1 {
                    // Repeatedly block the handshake in order to verify
                    // that renegotiate can handle Pending callbacks.
                    this.count -= 1;
                    Pending
                } else {
                    conn.set_server_name(&this.server_name)?;
                    Ready(Ok(()))
                }
            }
        }

        let count_per_handshake = 10;
        let expected_server_name = "helloworld";
        let initializer = TestInitializer {
            count: count_per_handshake,
            server_name: expected_server_name.to_owned(),
        };

        let (waker, wake_count) = new_count_waker();
        let reneg_callback = WakerRenegotiateCallback(waker.clone());

        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(reneg_callback)?;
        builder.set_connection_initializer(initializer)?;

        let mut pair = RenegotiateTestPair::from(builder)?;
        pair.client.set_waker(Some(&waker))?;

        pair.handshake().expect("Initial handshake");
        assert_eq!(wake_count, count_per_handshake);
        pair.send_renegotiate_request()
            .expect("Server sends request");
        pair.assert_renegotiate()?;
        assert_eq!(wake_count, count_per_handshake * 2);

        // Both the client and server should have the correct server name
        let server_name = pair.client.server_name();
        assert_eq!(Some(expected_server_name), server_name);
        let server_name = pair.server.ssl().servername(NameType::HOST_NAME);
        assert_eq!(Some(expected_server_name), server_name);

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
