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

use crate::{config::Config, connection::Connection, enums::CallbackResult, error::Error};
use core::{mem::ManuallyDrop, ptr::NonNull, task::Poll, time::Duration};
use pin_project_lite::pin_project;
use s2n_tls_sys::s2n_connection;
use std::{future::Future, pin::Pin};

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
/// Connection::poll_negotiate                                    (Rust)
/// |   s2n_negotiate                                             (C)
/// |   |   s2n_client_hello_cb                                   (C)
/// |   |   |   trigger_async_callback                            (Rust)
/// |   |   |   |   AsyncCallback::poll                           (Rust)
/// |   |   |   |   |   ClientHelloCallback::on_client_hello      (Rust)
/// |   |   |   |   |   +-> return Ok(Some(ConnectionFuture))     (Rust)
/// |   |   |   |   +-> return Poll::Pending                      (Rust)
/// |   |   |   +-> return Callback::Success                      (Rust)
/// |   |   +-> return S2N_SUCCESS                                (C)
/// |   +-> return S2N_ERR_T_BLOCKED                              (C)
/// +-> return Poll::Pending                                      (Rust)
///
/// Connection::poll_negotiate                                    (Rust)
/// |   AsyncCallback::poll                                       (Rust)
/// |   |   ConnectionFuture::poll                                (Rust)
/// |   |   +-> return Poll::Pending                              (Rust)
/// |   +-> return Poll::Pending                                  (Rust)
/// +-> return Poll::Pending                                      (Rust)
///
/// Connection::poll_negotiate                                    (Rust)
/// |   AsyncCallback::poll                                       (Rust)
/// |   |   ConnectionFuture::poll                                (Rust)
/// |   |   +-> return Poll::Ready                                (Rust)
/// |   +-> return Poll::Ready                                    (Rust)
/// |   s2n_negotiate                                             (C)
/// |
/// v   ...handshake continues.
///
/// Note that "s2n_client_hello_cb" is only called once.
/// After the initial call, the retries are handled by the Rust bindings.
/// s2n_negotiate is not called again until the callback completes.
///
pub(crate) fn trigger_async_callback<T: 'static + AsyncCallback>(
    callback: T,
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
    fn poll(
        // this should NEVER be a `&mut` since its would be possible to
        // mutate the Config on the Connection. Since one Config can be
        // used for multiple Connections that would be undefined-behavior
        &self,
        conn: &mut Connection,
    ) -> Poll<Result<(), Error>>;
}

/// The Future associated with the async [`ClientHelloCallback`] and stored
/// on the connection.
///
/// The calling application can provide an instance of [`ConnectionFuture`]
/// when implementing the [`ClientHelloCallback`] if it wants to run an
/// asynchronous operation (disk read, network call). The application can return
/// an error, [`Err(error::ApplicationError)`], to indicate failure and cancel the
/// connection.
///
/// [`ConfigResolver`] should be used if the application wants to set a new
/// [`Config`] on the connection.
pub trait ConnectionFuture {
    fn poll(
        self: Pin<&mut Self>,
        connection: &mut Connection,
        ctx: &mut core::task::Context,
    ) -> Poll<Result<(), Error>>;
}

pin_project! {
/// An implementation of [`ConnectionFuture`] which resolves the provided
/// future and sets the config on the [`connection::Connection`].
pub struct ConfigResolver<F: Future<Output = Result<Config, Error>>> {
    #[pin]
    fut: F,
}
}

impl<F: Future<Output = Result<Config, Error>>> ConfigResolver<F> {
    pub fn new(fut: F) -> Self {
        ConfigResolver { fut }
    }
}

impl<F: Future<Output = Result<Config, Error>>> ConnectionFuture for ConfigResolver<F> {
    fn poll(
        self: Pin<&mut Self>,
        connection: &mut Connection,
        ctx: &mut core::task::Context,
    ) -> Poll<Result<(), Error>> {
        let this = self.project();
        let config = match this.fut.poll(ctx) {
            Poll::Ready(config) => config?,
            Poll::Pending => return Poll::Pending,
        };

        connection.set_config(config)?;

        Poll::Ready(Ok(()))
    }
}

/// A trait for the callback executed after parsing the TLS Client Hello.
///
/// Use in conjunction with
/// [config::Builder::set_client_hello_callback](`crate::config::Builder::set_client_hello_callback()`).
pub trait ClientHelloCallback {
    /// The application can return a `Ok(None)` to resolve the client_hello_callback
    /// synchronously or return a `Ok(Some(ConnectionFuture))` if it wants to
    /// run some asynchronous task beforing resolving the callback.
    ///
    /// [`ConfigResolver`], which implements [`ConnectionFuture`] can be
    /// returned if the application wants to set a new [`Config`] on the connection.
    ///
    /// If the server_name is used to configure the connection then the application
    /// should call [`connection::Connection::server_name_extension_used()`].
    fn on_client_hello(
        // this should NEVER be a `&mut` since its would be possible to
        // mutate the Config on the Connection. Since one Config can be
        // used for multiple Connections that would be undefined-behavior
        &self,
        connection: &mut Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error>;
}

pub(crate) struct AsyncClientHelloCallback {}
impl AsyncCallback for AsyncClientHelloCallback {
    fn poll(&self, conn: &mut Connection) -> Poll<Result<(), Error>> {
        // if there is already a future set on the connection then take it and poll it
        if let Some(mut fut) = conn.take_client_hello_future() {
            let waker = conn.waker().ok_or(Error::CALLBACK_EXECUTION)?.clone();
            let mut ctx = core::task::Context::from_waker(&waker);
            match fut.as_mut().poll(conn, &mut ctx) {
                Poll::Ready(result) => {
                    let result = result.and_then(|_| conn.mark_client_hello_cb_done());
                    return Poll::Ready(result);
                }
                Poll::Pending => {
                    // replace the client_hello_future if it hasn't completed yet
                    conn.set_client_hello_future(fut);
                    return Poll::Pending;
                }
            }
        }

        // otherwise call the on_client_hello to make progress. storing the future if
        // the application provided one.
        let async_future = conn
            .config()
            .as_mut()
            .and_then(|config| config.context_mut().client_hello_callback.as_mut())
            .and_then(|callback| callback.on_client_hello(conn).transpose());
        match async_future {
            Some(fut) => {
                let mut fut = fut?;

                // Store the future on connection. This is Asynchronous resolution.
                let waker = conn.waker().ok_or(Error::CALLBACK_EXECUTION)?.clone();
                let mut ctx = core::task::Context::from_waker(&waker);
                match fut.as_mut().poll(conn, &mut ctx) {
                    Poll::Ready(result) => {
                        let result = result.and_then(|_| conn.mark_client_hello_cb_done());
                        Poll::Ready(result)
                    }
                    Poll::Pending => {
                        // replace the client_hello_future if it hasn't completed yet
                        conn.set_client_hello_future(fut);
                        return Poll::Pending;
                    }
                }
            }
            None => {
                // Done with the client_hello_callback. This is Synchronous resolution.
                Poll::Ready(conn.mark_client_hello_cb_done())
            }
        }
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

/// A trait for the callback used to retrieve the system / wall clock time.
pub trait WallClock {
    fn get_time_since_epoch(&self) -> Duration;
}

/// A trait for the callback used to retrieve the monotonic time.
pub trait MonotonicClock {
    fn get_time(&self) -> Duration;
}
