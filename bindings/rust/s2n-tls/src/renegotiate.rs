// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Methods to perform renegotiation.
//!
//! The use of renegotiation is strongly discouraged.
//! See [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/renegotiate.h).

use s2n_tls_sys::*;

use crate::{
    callbacks::with_context,
    config,
    connection::Connection,
    enums::CallbackResult,
    error::{Error, Fallible, Pollable},
};
use std::task::Poll;

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

/// A callback that triggers when the server requests renegotiation.
///
/// Returning "None" will result in the C callback returning an error,
/// canceling the connection.
///
/// See s2n_renegotiate_request_cb in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/renegotiate.h).
//
// This method returns Option instead of Result because the callback has no mechanism
// for surfacing errors to the application, so Result would be somewhat deceptive.
pub trait RenegotiateCallback: 'static + Send + Sync {
    fn on_renegotiate_request(
        &mut self,
        connection: &mut Connection,
    ) -> Option<RenegotiateResponse>;
}

impl RenegotiateCallback for RenegotiateResponse {
    fn on_renegotiate_request(&mut self, _conn: &mut Connection) -> Option<RenegotiateResponse> {
        Some(*self)
    }
}

impl Connection {
    /// Reset the connection so that it can be renegotiated.
    ///
    /// Returning "None" will result in the C callback returning an error,
    /// canceling the connection.
    ///
    /// See s2n_renegotiate_wipe in [the C API documentation](https://github.com/aws/s2n-tls/blob/main/api/unstable/renegotiate.h).
    /// The Rust equivalent of the connection-specific methods listed are:
    ///  - Methods to set the file descriptors: not currently supported by rust bindings
    ///  - Methods to set the send callback:
    ///    ([Connection::set_send_callback()], [Connection::set_send_context()])
    ///  - Methods to set the recv callback:
    ///    ([Connection::set_receive_callback()], [Connection::set_receive_context()])
    pub fn wipe_for_renegotiate(&mut self) -> Result<(), Error> {
        self.wipe_method(|conn| unsafe { s2n_renegotiate_wipe(conn.as_ptr()).into_result() })
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
        let mut blocked = s2n_blocked_status::NOT_BLOCKED;
        let buf_len: isize = buf.len().try_into().unwrap_or(0);
        let buf_ptr = buf.as_mut_ptr();
        let mut read: isize = 0;

        let r = self.poll_negotiate_method(|conn| {
            unsafe { s2n_renegotiate(conn.as_ptr(), buf_ptr, buf_len, &mut read, &mut blocked) }
                .into_poll()
        });
        (r, read.try_into().unwrap())
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
        task::Poll::{Pending, Ready},
    };

    // Currently renegotiation is not available from the openssl-sys bindings
    extern "C" {
        fn SSL_renegotiate(s: *mut openssl_sys::SSL) -> libc::size_t;
        fn SSL_renegotiate_pending(s: *mut openssl_sys::SSL) -> libc::size_t;
    }

    // std::task::ready is unstable
    fn unwrap_poll<T>(
        poll: Poll<Result<T, crate::error::Error>>,
    ) -> Result<(), crate::error::Error> {
        if let Ready(value) = poll {
            return value.map(|_| ());
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

        // Send and receive the hello request message, triggering renegotiate.
        // The result of s2n-tls receiving the request is returned.
        fn trigger_renegotiate(&mut self) -> Result<(), crate::error::Error> {
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
            let to_send = [0; 1];
            self.server
                .write_all(&to_send)
                .expect("Failed to write hello request");

            // s2n-tls needs to attempt to read data to receive the message
            let mut recv_buffer = [0; 1];
            unwrap_poll(self.client.poll_recv(&mut recv_buffer))
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

        fn assert_renegotiate(&mut self) {
            let mut empty = [0; 0];
            let mut buf = [0; 1];
            let mut result = Pending;
            while result.is_pending() {
                // openssl can only make progress by sending and receiving a 0-length array.
                // Both operations can fail for a number of irrelevant reasons while
                // still making progress, so we just ignore the results.
                _ = self.server.write(&empty);
                _ = self.server.read(&mut empty);

                let (r, n) = self.client.poll_renegotiate(&mut buf);
                assert_eq!(n, 0, "Unexpected application data");
                result = r;
            }
            unwrap_poll(result).expect("Renegotiate");
        }
    }

    #[test]
    fn ignore_callback() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Ignore)?;
        let mut pair = RenegotiateTestPair::from(builder)?;

        pair.handshake().expect("Initial handshake");

        // Expect receiving the hello request to be successful
        pair.trigger_renegotiate().expect("Trigger renegotiate");
        pair.send_and_receive().expect("Application data");

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
        // Expect receiving the hello request to be an error
        let error = pair.trigger_renegotiate().unwrap_err();
        assert_eq!(error.name(), "S2N_ERR_CANCELLED");

        Ok(())
    }

    #[test]
    fn reject_callback() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Reject)?;
        let mut pair = RenegotiateTestPair::from(builder)?;

        pair.handshake().expect("Initial handshake");
        // Expect handling the hello request to succeed.
        // s2n-tls doesn't fail when it rejects renegotiatation, it just sends
        // a warning alert. The peer chooses how to handle that alert.
        pair.trigger_renegotiate().expect("Trigger renegotiate");
        // The openssl server receives the alert on its next read.
        // Openssl considers the alert an error.
        let openssl_error = pair.send_and_receive().unwrap_err();
        assert!(openssl_error.to_string().contains("no renegotiation"));

        Ok(())
    }

    #[test]
    fn do_renegotiate() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Accept)?;
        let mut pair = RenegotiateTestPair::from(builder)?;

        pair.handshake().expect("Initial handshake");
        pair.trigger_renegotiate().expect("Trigger renegotiate");
        pair.send_and_receive()
            .expect("Application data before renegotiate");
        pair.client
            .wipe_for_renegotiate()
            .expect("Wipe for renegotiate");

        pair.assert_renegotiate();

        pair.send_and_receive()
            .expect("Application data after renegotiate");
        Ok(())
    }

    #[test]
    fn do_renegotiate_with_app_data() -> Result<(), Box<dyn Error>> {
        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Accept)?;
        let mut pair = RenegotiateTestPair::from(builder)?;

        pair.handshake().expect("Initial handshake");
        pair.trigger_renegotiate().expect("Trigger renegotiate");
        pair.send_and_receive()
            .expect("Application data before renegotiate");
        pair.client
            .wipe_for_renegotiate()
            .expect("Wipe for renegotiate");

        let to_write = "hello world";
        let mut buf = [0; 100];
        pair.server
            .write_all(to_write.as_bytes())
            .expect("Application data during renegotiate");
        let (result, n) = pair.client.poll_renegotiate(&mut buf);
        assert!(result.is_pending());
        assert_eq!(n, to_write.len(), "Incorrect application data");
        assert_eq!(&buf[..n], to_write.as_bytes());

        Ok(())
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

        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Accept)?;
        builder.set_private_key_callback(async_callback)?;
        let mut pair = RenegotiateTestPair::from(builder)?;

        let (waker, wake_count) = new_count_waker();
        pair.client.set_waker(Some(&waker))?;

        pair.handshake().expect("Initial handshake");
        assert_eq!(wake_count, count_per_handshake);
        pair.trigger_renegotiate().expect("Trigger renegotiate");
        pair.send_and_receive()
            .expect("Application data before renegotiate");
        pair.client
            .wipe_for_renegotiate()
            .expect("Wipe for renegotiate");
        // Reset the waker
        pair.client.set_waker(Some(&waker))?;

        pair.assert_renegotiate();
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

        let mut builder = config::Builder::new();
        builder.set_renegotiate_callback(RenegotiateResponse::Accept)?;
        builder.set_connection_initializer(initializer)?;
        let mut pair = RenegotiateTestPair::from(builder)?;

        let (waker, wake_count) = new_count_waker();
        pair.client.set_waker(Some(&waker))?;

        pair.handshake().expect("Initial handshake");
        assert_eq!(wake_count, count_per_handshake);
        pair.trigger_renegotiate().expect("Trigger renegotiate");
        pair.send_and_receive()
            .expect("Application data before renegotiate");
        pair.client
            .wipe_for_renegotiate()
            .expect("Wipe for renegotiate");
        // Verify that the wipe cleared the server name
        assert!(pair.client.server_name().is_none());
        // Reset the waker
        pair.client.set_waker(Some(&waker))?;

        pair.assert_renegotiate();
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
