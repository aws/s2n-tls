// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    connection::Connection,
    testing::{Context, Error, Result},
};
use bytes::BytesMut;
use core::task::Poll;
use libc::c_void;
use s2n_tls_sys::s2n_status_code::Type as s2n_status_code;

const SEND_BUFFER_CAPACITY: usize = 4096;

#[derive(Debug)]
pub struct Harness {
    connection: Connection,
    send_buffer: BytesMut,
    handshake_done: bool,
    // TODO add a size
}

impl Harness {
    pub fn new(connection: Connection) -> Self {
        Self {
            connection,
            send_buffer: BytesMut::new(),
            handshake_done: false,
        }
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }
}

impl super::Connection for Harness {
    fn poll_negotiate<Ctx: Context>(&mut self, context: &mut Ctx) -> Poll<Result<()>> {
        let mut callback: Callback<Ctx> = Callback {
            context,
            err: None,
            send_buffer: &mut self.send_buffer,
        };

        unsafe {
            // Safety: the callback struct must live as long as the callbacks are
            // set on on the connection
            callback.set(&mut self.connection);
        }

        let result = self.connection.poll_negotiate().map_ok(|_| ());

        callback.unset(&mut self.connection)?;

        match result {
            Poll::Ready(Ok(_)) => {
                if !self.handshake_done {
                    self.handshake_done = true;
                }
                Ok(()).into()
            }
            Poll::Ready(Err(err)) => Err(err.into()).into(),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_action<Ctx: Context, F>(&mut self, context: &mut Ctx, action: F) -> Poll<Result<()>>
    where
        F: FnOnce(&mut Connection) -> Poll<Result<usize, crate::error::Error>>,
    {
        let mut callback: Callback<Ctx> = Callback {
            context,
            err: None,
            send_buffer: &mut self.send_buffer,
        };

        unsafe {
            // Safety: the callback struct must live as long as the callbacks are
            // set on on the connection
            callback.set(&mut self.connection);
        }

        let result = action(&mut self.connection);

        callback.unset(&mut self.connection)?;

        match result {
            Poll::Ready(Ok(_)) => Ok(()).into(),
            Poll::Ready(Err(err)) => Err(err.into()).into(),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct Callback<'a, T> {
    pub context: &'a mut T,
    pub err: Option<Error>,
    pub send_buffer: &'a mut BytesMut,
}

impl<'a, T: 'a + Context> Callback<'a, T> {
    unsafe fn set(&mut self, connection: &mut Connection) {
        let context = self as *mut Self as *mut c_void;

        // We use unwrap here since s2n-tls will just check if connection is not null
        connection.set_send_callback(Some(Self::send_cb)).unwrap();
        connection.set_send_context(context).unwrap();
        connection
            .set_receive_callback(Some(Self::recv_cb))
            .unwrap();
        connection.set_receive_context(context).unwrap();
    }

    /// Removes all of the callback and context pointers from the connection
    pub fn unset(mut self, connection: &mut Connection) -> Result<()> {
        unsafe {
            unsafe extern "C" fn send_cb(
                _context: *mut c_void,
                _data: *const u8,
                _len: u32,
            ) -> s2n_status_code {
                -1
            }

            unsafe extern "C" fn recv_cb(
                _context: *mut c_void,
                _data: *mut u8,
                _len: u32,
            ) -> s2n_status_code {
                -1
            }

            // We use unwrap here since s2n-tls will just check if connection is not null
            connection.set_send_callback(Some(send_cb)).unwrap();
            connection.set_send_context(core::ptr::null_mut()).unwrap();
            connection.set_receive_callback(Some(recv_cb)).unwrap();
            connection
                .set_receive_context(core::ptr::null_mut())
                .unwrap();

            // Flush the send buffer before returning to the connection
            self.flush();

            if let Some(err) = self.err {
                return Err(err);
            }

            Ok(())
        }
    }

    unsafe extern "C" fn send_cb(
        context: *mut c_void,
        data: *const u8,
        len: u32,
    ) -> s2n_status_code {
        let context = &mut *(context as *mut Self);
        let data = core::slice::from_raw_parts(data, len as _);
        context.on_write(data) as _
    }

    /// Called when sending data
    fn on_write(&mut self, data: &[u8]) -> usize {
        // If this write would cause the current send buffer to reallocate,
        // we should flush and create a new send buffer.
        let remaining_capacity = self.send_buffer.capacity() - self.send_buffer.len();

        if remaining_capacity < data.len() {
            // Flush the send buffer before reallocating it
            self.flush();

            // ensure we only do one allocation for this write
            let len = SEND_BUFFER_CAPACITY.max(data.len());

            debug_assert!(
                self.send_buffer.is_empty(),
                "dropping a send buffer with data will result in data loss"
            );
            *self.send_buffer = BytesMut::with_capacity(len);
        }

        // Write the current data to the send buffer
        //
        // NOTE: we don't immediately flush to the context since s2n-tls may do
        //       several small writes in a row.
        self.send_buffer.extend_from_slice(data);

        data.len()
    }

    /// Flushes the send buffer into the context
    fn flush(&mut self) {
        if !self.send_buffer.is_empty() {
            let chunk = self.send_buffer.split().freeze();
            self.context.send(chunk);
        }
    }

    /// The function s2n-tls calls when it wants to receive data
    unsafe extern "C" fn recv_cb(context: *mut c_void, data: *mut u8, len: u32) -> s2n_status_code {
        let context = &mut *(context as *mut Self);
        let data = core::slice::from_raw_parts_mut(data, len as _);
        match context.on_read(data) {
            0 => {
                // https://aws.github.io/s2n-tls/doxygen/s2n_8h.html#a699fd9e05a8e8163811db6cab01af973
                // s2n-tls wants us to set the global errno to signal blocked
                errno::set_errno(errno::Errno(libc::EWOULDBLOCK));
                -1
            }
            len => len as _,
        }
    }

    /// Called when receiving data
    fn on_read(&mut self, data: &mut [u8]) -> usize {
        let max_len = Some(data.len());

        // TODO: loop until data buffer is full.
        if let Some(chunk) = self.context.receive(max_len) {
            let len = chunk.len();
            data[..len].copy_from_slice(&chunk);
            len
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        callbacks::{ClientHelloCallback, ConnectionFuture},
        enums::ClientAuthType,
        testing::{client_hello::*, s2n_tls::*, *},
    };
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;
    use futures_test::task::{new_count_waker, noop_waker};
    use std::{fs, path::Path, pin::Pin, sync::atomic::AtomicUsize};

    #[test]
    fn handshake_default() {
        let config = build_config(&security::DEFAULT).unwrap();
        establish_connection(config);
    }

    #[test]
    fn handshake_default_tls13() {
        let config = build_config(&security::DEFAULT_TLS13).unwrap();
        establish_connection(config)
    }

    #[test]
    fn default_config_and_clone_interaction() -> Result<(), Error> {
        let config = build_config(&security::DEFAULT_TLS13)?;
        assert_eq!(config.test_get_refcount()?, 1);
        {
            // Create new connection.
            let mut server = crate::connection::Connection::new_server();
            // Can't retrieve default config.
            assert!(server.config().is_none());
            // Custom config reference count doesn't change.
            assert_eq!(config.test_get_refcount()?, 1);

            // Set custom config on connection.
            server.set_config(config.clone())?;
            // Can retrieve custom config.
            assert!(server.config().is_some());
            // Custom config now referenced once more.
            assert_eq!(config.test_get_refcount()?, 2);

            // Create new connection.
            let mut client = crate::connection::Connection::new_client();
            // Can't retrieve default config.
            assert!(client.config().is_none());
            // Custom config reference count doesn't change.
            assert_eq!(config.test_get_refcount()?, 2);

            // Set custom config on connection.
            client.set_config(config.clone())?;
            // Can retrieve custom config.
            assert!(client.config().is_some());
            // Custom config now referenced once more.
            assert_eq!(config.test_get_refcount()?, 3);

            // drop all the clones
        }
        assert_eq!(config.test_get_refcount()?, 1);
        Ok(())
    }

    #[test]
    fn set_config_multiple_times() -> Result<(), Error> {
        let config = build_config(&security::DEFAULT_TLS13)?;
        assert_eq!(config.test_get_refcount()?, 1);

        let mut server = crate::connection::Connection::new_server();
        assert_eq!(config.test_get_refcount()?, 1);

        // call set_config once
        server.set_config(config.clone())?;
        assert_eq!(config.test_get_refcount()?, 2);
        assert!(server.config().is_some());

        // calling set_config multiple times works since we drop the previous config
        server.set_config(config.clone())?;
        assert_eq!(config.test_get_refcount()?, 2);
        assert!(server.config().is_some());
        Ok(())
    }

    #[test]
    fn connnection_waker() {
        let config = build_config(&security::DEFAULT_TLS13).unwrap();
        assert_eq!(config.test_get_refcount().unwrap(), 1);

        let mut server = crate::connection::Connection::new_server();
        server.set_config(config).unwrap();

        assert!(server.waker().is_none());

        let (waker, wake_count) = new_count_waker();
        server.set_waker(Some(&waker)).unwrap();
        assert!(server.waker().is_some());

        server.set_waker(None).unwrap();
        assert!(server.waker().is_none());

        assert_eq!(wake_count, 0);
    }

    #[test]
    fn failing_client_hello_callback_sync() -> Result<(), Error> {
        let (waker, wake_count) = new_count_waker();
        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_hello_callback(FailingCHHandler)?;
            config.build()?
        };

        let server = {
            // create and configure a server connection
            let mut server = crate::connection::Connection::new_server();
            server.set_config(config.clone())?;
            server.set_waker(Some(&waker))?;
            Harness::new(server)
        };

        let client = {
            // create a client connection
            let mut client = crate::connection::Connection::new_client();
            client.set_config(config)?;
            Harness::new(client)
        };

        let mut pair = Pair::new(server, client);
        loop {
            match pair.poll() {
                Poll::Ready(result) => {
                    let err = result.expect_err("handshake should fail");

                    // the underlying error should be the custom error the application provided
                    let s2n_err = err.downcast_ref::<crate::error::Error>().unwrap();
                    let app_err = s2n_err.application_error().unwrap();
                    let io_err = app_err.downcast_ref::<std::io::Error>().unwrap();
                    let _custom_err = io_err
                        .get_ref()
                        .unwrap()
                        .downcast_ref::<CustomError>()
                        .unwrap();
                    break;
                }
                Poll::Pending => continue,
            }
        }
        assert_eq!(wake_count, 0);

        Ok(())
    }

    #[test]
    fn failing_client_hello_callback_async() -> Result<(), Error> {
        let (waker, wake_count) = new_count_waker();
        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_hello_callback(FailingAsyncCHHandler)?;
            config.build()?
        };

        let server = {
            // create and configure a server connection
            let mut server = crate::connection::Connection::new_server();
            server.set_config(config.clone())?;
            server.set_waker(Some(&waker))?;
            Harness::new(server)
        };

        let client = {
            // create a client connection
            let mut client = crate::connection::Connection::new_client();
            client.set_config(config)?;
            Harness::new(client)
        };

        let mut pair = Pair::new(server, client);
        loop {
            match pair.poll() {
                Poll::Ready(result) => {
                    let err = result.expect_err("handshake should fail");

                    // the underlying error should be the custom error the application provided
                    let s2n_err = err.downcast_ref::<crate::error::Error>().unwrap();
                    let app_err = s2n_err.application_error().unwrap();
                    let io_err = app_err.downcast_ref::<std::io::Error>().unwrap();
                    let _custom_err = io_err
                        .get_ref()
                        .unwrap()
                        .downcast_ref::<CustomError>()
                        .unwrap();
                    break;
                }
                Poll::Pending => continue,
            }
        }
        // assert that the future is async returned Poll::Pending once
        assert_eq!(wake_count, 1);

        Ok(())
    }

    #[test]
    fn client_hello_callback_async() -> Result<(), Error> {
        let (waker, wake_count) = new_count_waker();
        let require_pending_count = 10;
        let handle = MockClientHelloHandler::new(require_pending_count);
        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_hello_callback(handle.clone())?;
            // multiple calls to set_client_hello_callback should succeed
            config.set_client_hello_callback(handle.clone())?;
            config.build()?
        };

        let server = {
            // create and configure a server connection
            let mut server = crate::connection::Connection::new_server();
            server.set_config(config.clone())?;
            server.set_waker(Some(&waker))?;
            Harness::new(server)
        };

        let client = {
            // create a client connection
            let mut client = crate::connection::Connection::new_client();
            client.set_config(config)?;
            Harness::new(client)
        };

        let pair = Pair::new(server, client);

        poll_tls_pair(pair);
        // confirm that the callback returned Pending `require_pending_count` times
        assert_eq!(wake_count, require_pending_count);
        // confirm that the final invoked count is +1 more than `require_pending_count`
        assert_eq!(
            handle.invoked.load(Ordering::SeqCst),
            require_pending_count + 1
        );

        Ok(())
    }
    #[test]
    fn client_hello_callback_sync() -> Result<(), Error> {
        let (waker, wake_count) = new_count_waker();
        #[derive(Clone)]
        struct ClientHelloSyncCallback(Arc<AtomicUsize>);
        impl ClientHelloSyncCallback {
            fn new() -> Self {
                ClientHelloSyncCallback(Arc::new(AtomicUsize::new(0)))
            }
            fn count(&self) -> usize {
                self.0.load(Ordering::Relaxed)
            }
        }
        impl ClientHelloCallback for ClientHelloSyncCallback {
            fn on_client_hello(
                &self,
                connection: &mut crate::connection::Connection,
            ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, crate::error::Error> {
                // Test that the config can be changed
                connection
                    .set_config(build_config(&security::DEFAULT_TLS13).unwrap())
                    .unwrap();

                // Test that server_name_extension_used can be invoked
                connection.server_name_extension_used();

                self.0.fetch_add(1, Ordering::Relaxed);

                // returning `None` indicates that the client_hello callback is
                // finished and the handshake can proceed.
                Ok(None)
            }
        }
        let callback = ClientHelloSyncCallback::new();

        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_hello_callback(callback.clone())?;
            config.build()?
        };

        let server = {
            // create and configure a server connection
            let mut server = crate::connection::Connection::new_server();
            server.set_config(config.clone())?;
            server.set_waker(Some(&waker))?;
            Harness::new(server)
        };

        let client = {
            // create a client connection
            let mut client = crate::connection::Connection::new_client();
            client.set_config(config)?;
            Harness::new(client)
        };

        let pair = Pair::new(server, client);

        assert_eq!(callback.count(), 0);
        poll_tls_pair(pair);
        assert_eq!(callback.count(), 1);
        assert_eq!(wake_count, 0);
        Ok(())
    }

    #[test]
    fn new_security_policy() -> Result<(), Error> {
        use crate::security::Policy;

        let policy = Policy::from_version("default")?;
        config_builder(&policy)?;
        Ok(())
    }

    #[test]
    fn trust_location() -> Result<(), Error> {
        let pem_dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../tests/pems"));
        let mut cert = pem_dir.to_path_buf();
        cert.push("rsa_4096_sha512_client_cert.pem");
        let mut key = pem_dir.to_path_buf();
        key.push("rsa_4096_sha512_client_key.pem");

        let mut builder = crate::config::Builder::new();
        builder.set_security_policy(&security::DEFAULT_TLS13)?;
        builder.set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;
        builder.load_pem(&fs::read(&cert)?, &fs::read(&key)?)?;
        builder.trust_location(Some(&cert), None)?;

        establish_connection(builder.build()?);
        Ok(())
    }

    /// `trust_location()` calls `s2n_config_set_verification_ca_location()`, which has the legacy behavior
    /// of enabling OCSP on clients. Since we do not want to replicate that behavior in the Rust bindings,
    /// this test verifies that `trust_location()` does not turn on OCSP. It also verifies that turning
    /// on OCSP explicitly still works when `trust_location()` is called.
    #[test]
    fn trust_location_does_not_change_ocsp_status() -> Result<(), Error> {
        let pem_dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../tests/pems"));
        let mut cert = pem_dir.to_path_buf();
        cert.push("rsa_4096_sha512_client_cert.pem");
        let mut key = pem_dir.to_path_buf();
        key.push("rsa_4096_sha512_client_key.pem");

        const OCSP_IANA_EXTENSION_ID: u16 = 5;

        for enable_ocsp in [true, false] {
            let config = {
                let mut config = crate::config::Builder::new();

                if enable_ocsp {
                    config.enable_ocsp()?;
                }

                config.set_security_policy(&security::DEFAULT_TLS13)?;
                config.set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;
                config.set_client_hello_callback(HasExtensionClientHelloHandler {
                    // This client hello handler will check for the OCSP extension
                    extension_iana: OCSP_IANA_EXTENSION_ID,
                    extension_expected: enable_ocsp,
                })?;
                config.load_pem(&fs::read(&cert)?, &fs::read(&key)?)?;
                config.trust_location(Some(&cert), None)?;
                config.build()?
            };

            let mut pair = tls_pair(config);
            pair.server
                .0
                .connection_mut()
                .set_waker(Some(&noop_waker()))?;

            poll_tls_pair(pair);
        }
        Ok(())
    }

    #[test]
    fn connection_level_verify_host_callback() -> Result<(), Error> {
        let reject_config = {
            let keypair = CertKeyPair::default();
            let mut config = crate::config::Builder::new();
            // configure the config VerifyHostNameCallback to reject all certificates
            config.set_verify_host_callback(RejectAllCertificatesHandler {})?;
            config.set_security_policy(&security::DEFAULT_TLS13)?;
            config.load_pem(keypair.cert(), keypair.key())?;
            config.trust_pem(keypair.cert())?;
            config.set_client_auth_type(ClientAuthType::Required)?;
            config.build()?
        };

        // confirm that default connection establishment fails
        let mut pair = tls_pair(reject_config.clone());
        assert!(poll_tls_pair_result(&mut pair).is_err());

        // confirm that overriding the verify_host_callback on connection causes
        // the handshake to succeed
        pair = tls_pair(reject_config);
        pair.server
            .0
            .connection
            .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
            .unwrap();
        pair.client
            .0
            .connection
            .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
            .unwrap();
        assert!(poll_tls_pair_result(&mut pair).is_ok());

        Ok(())
    }

    #[test]
    fn no_client_auth() -> Result<(), Error> {
        use crate::enums::ClientAuthType;

        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_auth_type(ClientAuthType::None)?;
            config.build()?
        };

        let server = {
            let mut server = crate::connection::Connection::new_server();
            server.set_config(config.clone())?;
            Harness::new(server)
        };

        let client = {
            let mut client = crate::connection::Connection::new_client();
            client.set_config(config)?;
            Harness::new(client)
        };

        let pair = Pair::new(server, client);
        let pair = poll_tls_pair(pair);
        let server = pair.server.0.connection;
        let client = pair.client.0.connection;

        for conn in [server, client] {
            assert!(!conn.client_cert_used());
            let cert = conn.client_cert_chain_bytes()?;
            assert!(cert.is_none());
            let sig_alg = conn.selected_client_signature_algorithm()?;
            assert!(sig_alg.is_none());
            let hash_alg = conn.selected_client_hash_algorithm()?;
            assert!(hash_alg.is_none());
        }

        Ok(())
    }

    #[test]
    fn client_auth() -> Result<(), Error> {
        use crate::enums::ClientAuthType;

        let config = {
            let mut config = config_builder(&security::DEFAULT_TLS13)?;
            config.set_client_auth_type(ClientAuthType::Optional)?;
            config.build()?
        };

        let server = {
            let mut server = crate::connection::Connection::new_server();
            server.set_config(config.clone())?;
            Harness::new(server)
        };

        let client = {
            let mut client = crate::connection::Connection::new_client();
            client.set_config(config)?;
            Harness::new(client)
        };

        let pair = Pair::new(server, client);
        let pair = poll_tls_pair(pair);
        let server = pair.server.0.connection;
        let client = pair.client.0.connection;

        let cert = server.client_cert_chain_bytes()?;
        assert!(cert.is_some());
        assert!(!cert.unwrap().is_empty());

        for conn in [server, client] {
            assert!(conn.client_cert_used());
            let sig_alg = conn.selected_client_signature_algorithm()?;
            assert!(sig_alg.is_some());
            let hash_alg = conn.selected_client_hash_algorithm()?;
            assert!(hash_alg.is_some());
        }

        Ok(())
    }

    #[test]
    fn system_certs_loaded_by_default() {
        let keypair = CertKeyPair::default();

        // Load the server certificate into the trust store by overriding the OpenSSL default
        // certificate location.
        temp_env::with_var("SSL_CERT_FILE", Some(keypair.cert_path()), || {
            let mut builder = Builder::new();
            builder
                .load_pem(keypair.cert(), keypair.key())
                .unwrap()
                .set_security_policy(&security::DEFAULT_TLS13)
                .unwrap()
                .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
                .unwrap();

            let config = builder.build().unwrap();
            establish_connection(config);
        });
    }

    #[test]
    fn disable_loading_system_certs() {
        let keypair = CertKeyPair::default();

        // Load the server certificate into the trust store by overriding the OpenSSL default
        // certificate location.
        temp_env::with_var("SSL_CERT_FILE", Some(keypair.cert_path()), || {
            let mut builder = Builder::new();
            builder
                .load_pem(keypair.cert(), keypair.key())
                .unwrap()
                .set_security_policy(&security::DEFAULT_TLS13)
                .unwrap()
                .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
                .unwrap();

            // Disable loading system certificates
            builder.with_system_certs(false).unwrap();

            let config = builder.build().unwrap();
            let mut config_with_system_certs = config.clone();

            let mut pair = tls_pair(config);

            // System certificates should not be loaded into the trust store. The handshake
            // should fail since the certificate should not be trusted.
            assert!(poll_tls_pair_result(&mut pair).is_err());

            // The handshake should succeed after trusting the certificate.
            unsafe {
                s2n_tls_sys::s2n_config_load_system_certs(config_with_system_certs.as_mut_ptr());
            }
            establish_connection(config_with_system_certs);
        });
    }
}
