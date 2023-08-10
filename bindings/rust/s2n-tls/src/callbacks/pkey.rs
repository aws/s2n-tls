// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    callbacks::*,
    connection::Connection,
    enums::{HashAlgorithm, Mode, SignatureAlgorithm},
    error::{Error, Fallible},
    ffi::*,
};
use std::{pin::Pin, ptr::NonNull};

#[non_exhaustive]
#[derive(Debug)]
pub enum OperationType {
    Decrypt,
    Sign(SignatureAlgorithm, HashAlgorithm),
}

pub struct PrivateKeyOperation {
    raw: NonNull<s2n_async_pkey_op>,
    kind: OperationType,
}

/// # Safety
///
/// Safety: s2n_async_pkey_op objects can be sent across threads
unsafe impl Send for PrivateKeyOperation {}

/// # Safety
///
/// Safety: All C methods that mutate the s2n_async_pkey_op are wrapped
/// in Rust methods that require a mutable reference.
unsafe impl Sync for PrivateKeyOperation {}

impl PrivateKeyOperation {
    pub(crate) fn try_from_cb(
        conn: &Connection,
        op_ptr: *mut s2n_async_pkey_op,
    ) -> Result<Self, Error> {
        let mut raw_kind = 0;
        unsafe { s2n_async_pkey_op_get_op_type(op_ptr, &mut raw_kind) }.into_result()?;

        let kind = match raw_kind {
            s2n_async_pkey_op_type::SIGN => {
                let sig_alg = match conn.mode() {
                    Mode::Client => conn
                        .selected_client_signature_algorithm()?
                        .ok_or(Error::INVALID_INPUT)?,
                    Mode::Server => conn.selected_signature_algorithm()?,
                };
                let hash_alg = match conn.mode() {
                    Mode::Client => conn
                        .selected_client_hash_algorithm()?
                        .ok_or(Error::INVALID_INPUT)?,
                    Mode::Server => conn.selected_hash_algorithm()?,
                };
                OperationType::Sign(sig_alg, hash_alg)
            }
            s2n_async_pkey_op_type::DECRYPT => OperationType::Decrypt,
            _ => return Err(Error::INVALID_INPUT),
        };

        let raw = NonNull::new(op_ptr).ok_or(Error::INVALID_INPUT)?;
        Ok(PrivateKeyOperation { raw, kind })
    }

    /// Do we need to sign or decrypt with the private key?
    pub fn kind(&self) -> Result<&OperationType, Error> {
        Ok(&self.kind)
    }

    /// The size of the slice returned by [`input()`]
    pub fn input_size(&self) -> Result<usize, Error> {
        let mut size = 0;
        unsafe { s2n_async_pkey_op_get_input_size(self.raw.as_ptr(), &mut size) }.into_result()?;
        size.try_into().map_err(|_| Error::INVALID_INPUT)
    }

    /// Provides the input for the operation.
    ///
    /// If this is an [`OperationType::Sign`] operation, then this input has
    /// already been hashed and is the resultant digest.
    pub fn input(&self, buf: &mut [u8]) -> Result<(), Error> {
        let buf_len: u32 = buf.len().try_into().map_err(|_| Error::INVALID_INPUT)?;
        let buf_ptr = buf.as_ptr() as *mut u8;
        unsafe { s2n_async_pkey_op_get_input(self.raw.as_ptr(), buf_ptr, buf_len) }
            .into_result()?;
        Ok(())
    }

    /// Sets the output of the operation
    pub fn set_output(self, conn: &mut Connection, buf: &[u8]) -> Result<(), Error> {
        let buf_len: u32 = buf.len().try_into().map_err(|_| Error::INVALID_INPUT)?;
        let buf_ptr = buf.as_ptr() as *const u8;
        unsafe {
            s2n_async_pkey_op_set_output(self.raw.as_ptr(), buf_ptr, buf_len).into_result()?;
            s2n_async_pkey_op_apply(self.raw.as_ptr(), conn.as_ptr()).into_result()?;
        }
        Ok(())
    }
}

impl Drop for PrivateKeyOperation {
    fn drop(&mut self) {
        unsafe {
            let _ = s2n_async_pkey_op_free(self.raw.as_ptr());
        }
    }
}

pub trait PrivateKeyCallback {
    fn handle_operation(
        &self,
        connection: &mut Connection,
        operation: PrivateKeyOperation,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config, connection, error, security, testing,
        testing::{s2n_tls::*, *},
    };
    use core::task::{Poll, Waker};
    use futures_test::task::new_count_waker;
    use openssl::{ec::EcKey, ecdsa::EcdsaSig};

    type Error = Box<dyn std::error::Error>;

    const KEY: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/pems/ecdsa_p384_pkcs1_key.pem"
    ));
    const CERT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/pems/ecdsa_p384_pkcs1_cert.pem"
    ));

    fn new_pair<T>(
        callback: T,
        waker: Waker,
    ) -> Result<Pair<s2n_tls::Harness, s2n_tls::Harness>, Error>
    where
        T: 'static + PrivateKeyCallback,
    {
        let config = {
            let mut config = config::Builder::new();
            config.set_security_policy(&security::DEFAULT_TLS13)?;
            config.load_public_pem(CERT)?;
            config.set_private_key_callback(callback)?;
            // Our test certificates are untrusted, but disabling certificate
            // verification does not affect handshake signatures.
            unsafe { config.disable_x509_verification() }?;
            config.build()?
        };

        let server = {
            let mut server = connection::Connection::new_server();
            server.set_config(config.clone())?;
            server.set_waker(Some(&waker))?;
            Harness::new(server)
        };

        let client = {
            let mut client = connection::Connection::new_client();
            client.set_config(config)?;
            Harness::new(client)
        };

        Ok(Pair::new(server, client))
    }

    fn ecdsa_sign(
        op: PrivateKeyOperation,
        conn: &mut connection::Connection,
        key: &[u8],
    ) -> Result<(), error::Error> {
        match op.kind()? {
            OperationType::Sign(SignatureAlgorithm::ECDSA, _) => {
                let in_buf_size = op.input_size()?;
                let mut in_buf = vec![0; in_buf_size];
                op.input(&mut in_buf)?;

                let key =
                    EcKey::private_key_from_pem(key).expect("Failed to create EcKey from pem");
                let sig = EcdsaSig::sign(&in_buf, &key).expect("Failed to sign input");
                let out = sig.to_der().expect("Failed to convert signature to der");

                op.set_output(conn, &out)?;
            }
            _ => panic!("Unexpected pkey operation"),
        }
        Ok(())
    }

    #[test]
    fn sync_offload_success() -> Result<(), Error> {
        struct TestPkeyCallback(Counter);
        impl PrivateKeyCallback for TestPkeyCallback {
            fn handle_operation(
                &self,
                conn: &mut connection::Connection,
                op: PrivateKeyOperation,
            ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, error::Error> {
                self.0.increment();
                ecdsa_sign(op, conn, KEY)?;
                Ok(None)
            }
        }

        let (waker, wake_count) = new_count_waker();
        let counter = testing::Counter::default();
        let callback = TestPkeyCallback(counter.clone());
        let pair = new_pair(callback, waker)?;

        assert_eq!(counter.count(), 0);
        assert_eq!(wake_count, 0);
        poll_tls_pair(pair);
        assert_eq!(counter.count(), 1);
        assert_eq!(wake_count, 0);

        Ok(())
    }

    #[test]
    fn async_offload_success() -> Result<(), Error> {
        const POLL_COUNT: usize = 10;

        struct TestPkeyFuture {
            counter: usize,
            op: Option<PrivateKeyOperation>,
        }
        impl ConnectionFuture for TestPkeyFuture {
            fn poll(
                mut self: Pin<&mut Self>,
                conn: &mut connection::Connection,
                ctx: &mut core::task::Context,
            ) -> Poll<Result<(), error::Error>> {
                ctx.waker().wake_by_ref();
                self.counter += 1;
                if self.counter < POLL_COUNT {
                    Poll::Pending
                } else if let Some(op) = self.op.take() {
                    Poll::Ready(ecdsa_sign(op, conn, KEY))
                } else {
                    Poll::Ready(Err(error::Error::application(
                        "missing pkey operation".into(),
                    )))
                }
            }
        }

        struct TestPkeyCallback(Counter);
        impl PrivateKeyCallback for TestPkeyCallback {
            fn handle_operation(
                &self,
                _conn: &mut connection::Connection,
                op: PrivateKeyOperation,
            ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, error::Error> {
                self.0.increment();
                let future = TestPkeyFuture {
                    counter: 0,
                    op: Some(op),
                };
                Ok(Some(Box::pin(future)))
            }
        }

        let (waker, wake_count) = new_count_waker();
        let counter = testing::Counter::default();
        let callback = TestPkeyCallback(counter.clone());
        let pair = new_pair(callback, waker)?;

        assert_eq!(counter.count(), 0);
        assert_eq!(wake_count, 0);
        poll_tls_pair(pair);
        assert_eq!(counter.count(), 1);
        assert_eq!(wake_count, POLL_COUNT);

        Ok(())
    }

    #[test]
    fn sync_failure() -> Result<(), Error> {
        const ERROR: &str = "sync_failure error";

        struct TestPkeyCallback(Counter);
        impl PrivateKeyCallback for TestPkeyCallback {
            fn handle_operation(
                &self,
                _conn: &mut connection::Connection,
                _op: PrivateKeyOperation,
            ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, error::Error> {
                self.0.increment();
                Err(testing::test_error(ERROR))
            }
        }

        let (waker, wake_count) = new_count_waker();
        let counter = testing::Counter::default();
        let callback = TestPkeyCallback(counter.clone());
        let mut pair = new_pair(callback, waker)?;

        assert_eq!(counter.count(), 0);
        assert_eq!(wake_count, 0);
        let result = poll_tls_pair_result(&mut pair);
        assert_eq!(counter.count(), 1);
        assert_eq!(wake_count, 0);

        match result {
            Ok(_) => panic!("Handshake unexpectedly succeeded"),
            Err(e) => testing::assert_test_error(e, ERROR),
        };
        Ok(())
    }

    #[test]
    fn async_failure() -> Result<(), Error> {
        const POLL_COUNT: usize = 10;
        const ERROR: &str = "async_failure error";

        struct TestPkeyFuture {
            counter: usize,
            _op: PrivateKeyOperation,
        }
        impl ConnectionFuture for TestPkeyFuture {
            fn poll(
                mut self: Pin<&mut Self>,
                _conn: &mut connection::Connection,
                ctx: &mut core::task::Context,
            ) -> Poll<Result<(), error::Error>> {
                ctx.waker().wake_by_ref();
                self.counter += 1;
                if self.counter < POLL_COUNT {
                    Poll::Pending
                } else {
                    Poll::Ready(Err(testing::test_error(ERROR)))
                }
            }
        }

        struct TestPkeyCallback(Counter);
        impl PrivateKeyCallback for TestPkeyCallback {
            fn handle_operation(
                &self,
                _conn: &mut connection::Connection,
                _op: PrivateKeyOperation,
            ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, error::Error> {
                self.0.increment();
                let future = TestPkeyFuture { counter: 0, _op };
                Ok(Some(Box::pin(future)))
            }
        }

        let (waker, wake_count) = new_count_waker();
        let counter = testing::Counter::default();
        let callback = TestPkeyCallback(counter.clone());
        let mut pair = new_pair(callback, waker)?;

        assert_eq!(counter.count(), 0);
        assert_eq!(wake_count, 0);
        let result = poll_tls_pair_result(&mut pair);
        assert_eq!(counter.count(), 1);
        assert_eq!(wake_count, POLL_COUNT);

        match result {
            Ok(_) => panic!("Handshake unexpectedly succeeded"),
            Err(e) => testing::assert_test_error(e, ERROR),
        };
        Ok(())
    }
}
