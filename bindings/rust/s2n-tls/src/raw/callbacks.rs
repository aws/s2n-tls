// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::raw::{connection::Connection, enums::CallbackResult, error::Error};
use core::{mem::ManuallyDrop, ptr::NonNull, task::Poll};
use s2n_tls_sys::s2n_connection;

const READY_OK: Poll<Result<(), Error>> = Poll::Ready(Ok(()));

/// Convert the connection pointer provided to a callback into a Connection
/// useable with the Rust bindings.
///
/// # Safety
///
/// This must ONLY be used for connection pointers provided to callbacks,
/// which can be assumed to point to valid Connections because the
/// callbacks were configured through the Rust bindings.
pub unsafe fn with_connection<F, T>(conn_ptr: *mut s2n_connection, action: F) -> T
where
    F: FnOnce(&mut Connection) -> T,
{
    let raw = NonNull::new(conn_ptr).expect("connection should not be null");
    let mut conn = Connection::from_raw(raw);
    let r = action(&mut conn);
    let _ = ManuallyDrop::new(conn);
    r
}

pub(crate) trait AsyncCallback {
    fn poll(&self, conn: &mut Connection) -> Poll<Result<(), Error>>;
}

pub(crate) trait AsyncCallbackExt {
    fn trigger(self, conn: &mut Connection) -> CallbackResult;
}

impl<T: 'static + AsyncCallback> AsyncCallbackExt for T {
    fn trigger(self, conn: &mut Connection) -> CallbackResult {
        // Try once first.
        match self.poll(conn) {
            // If callback completes, no need for retry.
            Poll::Ready(r) => r.into(),
            // If callback doesn't complete, prepare connection for retry.
            Poll::Pending => {
                conn.set_pending_callback(Some(Box::new(self)));
                CallbackResult::Success
            }
        }
    }
}

/// This trait represents the callback which is run after parsing the client_hello.
///
/// Use in conjunction with [`config::Builder::set_client_hello_handler()`].
/// Can be synchronous or asynchronous.
pub trait ClientHelloCallback {
    fn poll_client_hello(&self, connection: &mut Connection) -> Poll<Result<(), Error>>;
}

pub(crate) struct AsyncClientHelloCallback {}
impl AsyncCallback for AsyncClientHelloCallback {
    fn poll(&self, conn: &mut Connection) -> Poll<Result<(), Error>> {
        let config = conn.config()?;
        let result = config
            .as_ref()
            .and_then(|config| config.context().client_hello_handler.as_ref())
            .map(|callback| callback.poll_client_hello(conn))
            .unwrap_or(READY_OK);
        if result == READY_OK {
            conn.mark_client_hello_cb_done()?;
        }
        result
    }
}

/// Trait which a user must implement to verify host name(s) during X509 verification
pub trait VerifyHostNameCallback {
    /// The implementation shall verify the host name by returning `true` if the certificate host name is valid,
    /// and `false` otherwise.
    fn verify_host_name(&self, host_name: &str) -> bool;
}
