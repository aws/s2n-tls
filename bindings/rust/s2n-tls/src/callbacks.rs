// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Utilities to handle passing Rust code to s2n-tls's C callbacks.
//!
//! s2n-tls uses callbacks to temporarily return control to the application
//! and allow the application to execute custom code.
//!
//! To use a callback in your application, just implement the trait for the
//! target callback type and pass your implementation to the appropriate
//! connection or config method. For example, you can implement
//! [`ClientHelloCallback`] and pass that implementation to
//! [config::Builder::set_client_hello_callback()](`crate::config::Builder::set_client_hello_callback()`)
//! in order to execute custom logic after an s2n-tls server receives a client hello.
//!
//! s2n-tls callbacks come in two flavors:
//! * "sync" callbacks return an immediate result and will block the task
//!   performing the handshake until they return success or failure. See
//!   [`VerifyHostNameCallback`] as an example.
//! * "async" callbacks return a [`Poll`] and should not block the task performing the handshake.
//!   They will be polled until they return [`Poll::Ready`].
//!   [Connection::waker()](`crate::connection::Connection::waker()`)
//!   can be used to register the task for wakeup. See [`ClientHelloCallback`] as an example.

use crate::{connection::Connection, enums::CallbackResult, error::Error};
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
pub(crate) unsafe fn with_connection<F, T>(conn_ptr: *mut s2n_connection, action: F) -> T
where
    F: FnOnce(&mut Connection) -> T,
{
    let raw = NonNull::new(conn_ptr).expect("connection should not be null");
    let mut conn = Connection::from_raw(raw);
    let r = action(&mut conn);
    // Since this is a callback, it receives a pointer to the connection
    // but doesn't own that connection or control its lifecycle.
    // Do not drop / free the connection.
    let _ = ManuallyDrop::new(conn);
    r
}

/// Begins execution of an asyc callback.
///
/// Polls the async callback once, then registers it for later retries if
/// necessary.
///
/// The C-style callback method passed to the underlying s2n-tls implementation
/// should call this method instead of using the Rust callback implementation
/// directly. The C-style callback will only execute once, so this method
/// ensures that the Rust callback implementation is polled until it completes.
///
/// Using [`config::set_client_hello_callback`] as an example, the
/// execution roughly looks like:
///
/// Connection::negotiate                       (Rust)
/// |   s2n_negotiate                           (C)
/// |   |   s2n_client_hello_cb                 (C)
/// |   |   |   trigger_async_callback          (Rust)
/// |   |   |   |   AsyncCallback::poll         (Rust)
/// |   |   |   |   +-> return Poll::Pending    (Rust)
/// |   |   |   +-> return Callback::Success    (Rust)
/// |   |   +-> return S2N_SUCCESS              (C)
/// |   +-> return S2N_ERR_T_BLOCKED            (C)
/// +-> return Poll::Pending                    (Rust)
///
/// Connection::negotiate                       (Rust)
/// |   AsyncCallback::poll                     (Rust)
/// |   +-> return Poll::Pending                (Rust)
/// +-> return Poll::Pending                    (Rust)
///
/// Connection::negotiate                       (Rust)
/// |   AsyncCallback::poll                     (Rust)
/// |   +-> return Poll::Ready                  (Rust)
/// |   s2n_negotiate                           (C)
/// |                          
/// v   ...handshake continues.
///
/// Note that "s2n_client_hello_cb" is only called once.
/// After the initial call, the retries are handled by the Rust bindings.
/// s2n_negotiate is not called again until the callback completes.
///
pub(crate) fn trigger_async_callback<T: 'static + AsyncCallback>(
    mut callback: T,
    conn: &mut Connection,
) -> CallbackResult {
    // Try once first.
    match callback.poll(conn) {
        // If callback completes, no need for retry.
        Poll::Ready(r) => r.into(),
        // If callback doesn't complete, prepare connection for retry.
        Poll::Pending => {
            conn.set_pending_callback(Some(Box::new(callback)));
            CallbackResult::Success
        }
    }
}

/// An asynchronous adapter for an s2n-tls callback.
///
/// This trait must be implemented for any asynchronous callbacks
/// supported by the bindings.
///
/// Implementations should capture any arguments passed to the callback
/// so that they will be available for every call to [`AsyncCallback::poll`].
/// [`AsyncCallback::poll`] should handle retrieving the callback from
/// the connection or config, passing it the stored arguments,
/// and calling any "mark done" style methods necessary to unblock the
/// connection once the callback has succeeded.
pub(crate) trait AsyncCallback {
    fn poll(&mut self, conn: &mut Connection) -> Poll<Result<(), Error>>;
}

/// A trait for the callback executed after parsing the TLS Client Hello.
///
/// Use in conjunction with
/// [config::Builder::set_client_hello_callback](`crate::config::Builder::set_client_hello_callback()`).
pub trait ClientHelloCallback {
    fn poll_client_hello(&self, connection: &mut Connection) -> Poll<Result<(), Error>>;
}

pub(crate) struct AsyncClientHelloCallback {}
impl AsyncCallback for AsyncClientHelloCallback {
    fn poll(&mut self, conn: &mut Connection) -> Poll<Result<(), Error>> {
        let result = conn
            .config()
            .as_ref()
            .and_then(|config| config.context().client_hello_callback.as_ref())
            .map(|callback| callback.poll_client_hello(conn))
            .unwrap_or(READY_OK);
        if result == READY_OK {
            conn.mark_client_hello_cb_done()?;
        }
        result
    }
}

/// A trait for the callback used to verify host name(s) during X509
/// verification.
///
/// The implementation should verify the certificate host name and return `true`
/// if the name is valid, `false` otherwise.
pub trait VerifyHostNameCallback {
    fn verify_host_name(&self, host_name: &str) -> bool;
}
