// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    callbacks::{ClientHelloCallback, ConnectionFuture},
    error, security,
};
use alloc::sync::Arc;
use core::{sync::atomic::Ordering, task::Poll};
use s2n_tls_sys::{s2n_client_hello_has_extension, s2n_connection_get_client_hello};
use std::{fmt, io, pin::Pin, sync::atomic::AtomicUsize};

// The Future returned by MockClientHelloHandler.
//
// An instance of this Future is stored on the connection and
// polled to make progress in the async client_hello_callback
pub struct MockClientHelloFuture {
    require_pending_count: usize,
    invoked: Arc<AtomicUsize>,
}

impl ConnectionFuture for MockClientHelloFuture {
    fn poll(
        self: Pin<&mut Self>,
        connection: &mut crate::connection::Connection,
        _ctx: &mut core::task::Context,
    ) -> Poll<Result<(), error::Error>> {
        if self.invoked.fetch_add(1, Ordering::SeqCst) < self.require_pending_count {
            // confirm the callback can access the waker
            connection.waker().unwrap().wake_by_ref();
            return Poll::Pending;
        }

        // Test that the config can be changed
        connection
            .set_config(super::build_config(&security::DEFAULT_TLS13).unwrap())
            .unwrap();

        // Test that server_name_extension_used can be invoked
        connection.server_name_extension_used();

        Poll::Ready(Ok(()))
    }
}

#[derive(Clone)]
pub struct MockClientHelloHandler {
    require_pending_count: usize,
    pub invoked: Arc<AtomicUsize>,
}

impl MockClientHelloHandler {
    pub fn new(require_pending_count: usize) -> Self {
        Self {
            require_pending_count,
            invoked: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl ClientHelloCallback for MockClientHelloHandler {
    fn on_client_hello(
        &self,
        _connection: &mut crate::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, crate::error::Error> {
        let fut = MockClientHelloFuture {
            require_pending_count: self.require_pending_count,
            invoked: self.invoked.clone(),
        };

        // returning `Some` indicates that the client_hello callback is
        // not yet finished and that the supplied MockClientHelloFuture
        // needs to be `poll`ed to make progress.
        Ok(Some(Box::pin(fut)))
    }
}

// A ClientHelloCallback which returns a Asynchronous task, which
// eventually returns an error.
#[derive(Default)]
pub struct FailingCHHandler;

impl ClientHelloCallback for FailingCHHandler {
    fn on_client_hello(
        &self,
        _connection: &mut crate::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, error::Error> {
        let io_error = io::Error::new(io::ErrorKind::Other, CustomError);
        Err(crate::error::Error::application(Box::new(io_error)))
    }
}

#[derive(Default)]
pub struct FailingAsyncCHHandler;
impl ClientHelloCallback for FailingAsyncCHHandler {
    fn on_client_hello(
        &self,
        _connection: &mut crate::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, error::Error> {
        let fut = FailingCHFuture::default();
        Ok(Some(Box::pin(fut)))
    }
}

// A ClientHelloCallback which returns a synchronous error.
#[derive(Default)]
struct FailingCHFuture {
    pub invoked: Arc<AtomicUsize>,
}

impl ConnectionFuture for FailingCHFuture {
    fn poll(
        self: Pin<&mut Self>,
        connection: &mut crate::connection::Connection,
        _ctx: &mut core::task::Context,
    ) -> Poll<Result<(), error::Error>> {
        if self.invoked.fetch_add(1, Ordering::SeqCst) < 1 {
            // confirm the callback can access the waker
            connection.waker().unwrap().wake_by_ref();
            return Poll::Pending;
        }

        let io_error = io::Error::new(io::ErrorKind::Other, CustomError);
        let ret = Err(crate::error::Error::application(Box::new(io_error)));
        Poll::Ready(ret)
    }
}

impl Drop for FailingCHFuture {
    // return pending once to simulate the async nature of the future and
    // improve test coverage
    fn drop(&mut self) {
        assert!(self.invoked.load(Ordering::SeqCst) >= 1);
    }
}
/// A client hello handler that asserts that the extension with the given
/// IANA code is either present or not present in the client hello
pub struct HasExtensionClientHelloHandler {
    pub extension_iana: u16,
    pub extension_expected: bool,
}

impl ClientHelloCallback for HasExtensionClientHelloHandler {
    fn on_client_hello(
        &self,
        connection: &mut crate::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, error::Error> {
        let mut exists = false;

        unsafe {
            let client_hello = s2n_connection_get_client_hello(connection.as_ptr());
            s2n_client_hello_has_extension(client_hello, self.extension_iana, &mut exists as _);
        }

        if self.extension_expected {
            assert!(
                exists,
                "Extension {} was not found in the client hello",
                self.extension_iana
            );
        } else {
            assert!(
                !exists,
                "Unexpected extension {} found in the client hello",
                self.extension_iana
            )
        }

        Ok(None)
    }
}

#[derive(Debug)]
pub struct CustomError;

impl std::error::Error for CustomError {}
impl fmt::Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "custom error")
    }
}
