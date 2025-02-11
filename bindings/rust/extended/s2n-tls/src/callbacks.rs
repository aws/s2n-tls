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
//! * "async" callbacks return a [Poll](`core::task::Poll`) and should not block the task performing the handshake.
//!   They will be polled until they return [Poll::Ready](`core::task::Poll::Ready`).
//!   [Connection::waker()](`crate::connection::Connection::waker()`)
//!   can be used to register the task for wakeup. See [`ClientHelloCallback`] as an example.

use crate::{config::Context, connection::Connection};
use core::{mem::ManuallyDrop, ptr::NonNull, time::Duration};
use s2n_tls_sys::s2n_connection;

mod async_cb;
pub use async_cb::*;

mod client_hello;
pub use client_hello::*;

mod session_ticket;
pub use session_ticket::*;

mod pkey;
pub use pkey::*;

/// Convert the connection pointer provided to a callback into a Connection
/// and Context useable with the Rust bindings.
///
/// # Safety
///
/// This must ONLY be used for connection pointers provided to callbacks,
/// which can be assumed to point to valid Connections because the
/// callbacks were configured through the Rust bindings.
pub(crate) unsafe fn with_context<F, T>(conn_ptr: *mut s2n_connection, action: F) -> T
where
    F: FnOnce(&mut Connection, &Context) -> T,
{
    let raw = NonNull::new(conn_ptr).expect("connection should not be null");
    // Since this is a callback, it receives a pointer to the connection
    // but doesn't own that connection or control its lifecycle.
    // Do not drop / free the connection.
    // We must make the connection `ManuallyDrop` before `action`, otherwise a panic
    // in `action` would cause the unwind mechanism to drop the connection.
    let mut conn = ManuallyDrop::new(Connection::from_raw(raw));
    let config = conn.config().expect("config should not be null");
    let context = config.context();
    action(&mut conn, context)
}

/// A trait for the callback used to verify host name(s) during X509
/// verification.
///
/// The implementation should verify the certificate host name and return `true`
/// if the name is valid, `false` otherwise.
pub trait VerifyHostNameCallback: 'static + Send + Sync {
    fn verify_host_name(&self, host_name: &str) -> bool;
}

/// A trait for the callback used to retrieve the system / wall clock time.
pub trait WallClock: 'static + Send + Sync {
    fn get_time_since_epoch(&self) -> Duration;
}

/// A trait for the callback used to retrieve the monotonic time.
pub trait MonotonicClock: 'static + Send + Sync {
    fn get_time(&self) -> Duration;
}

/// Invoke the user provided VerifyHostNameCallback on the host_name.
///
/// # Safety
///
/// The caller must ensure that the memory underlying host_name is a valid
/// slice.
pub(crate) unsafe fn verify_host(
    host_name: *const ::libc::c_char,
    host_name_len: usize,
    handler: &mut Box<dyn VerifyHostNameCallback>,
) -> u8 {
    let host_name = host_name as *const u8;
    let host_name = core::slice::from_raw_parts(host_name, host_name_len);

    match core::str::from_utf8(host_name) {
        Ok(host_name_str) => handler.verify_host_name(host_name_str) as u8,
        Err(_) => 0, // If the host name can't be parsed, fail closed.
    }
}

#[cfg(test)]
mod tests {
    use crate::{callbacks::with_context, config::Config, connection::Builder, enums::Mode};

    // The temporary connection created in `with_context` should never be freed,
    // even if customer code panics.
    #[test]
    fn panic_does_not_free_connection() -> Result<(), crate::error::Error> {
        let config = Config::new();
        let mut connection = config.build_connection(Mode::Server)?;

        // 1 connection + 1 self reference
        assert_eq!(config.test_get_refcount()?, 2);

        let conn_ptr = connection.as_ptr();
        let unwind_result = std::panic::catch_unwind(|| {
            unsafe {
                with_context(conn_ptr, |_conn, _context| {
                    panic!("force unwind");
                })
            };
        });

        // a panic happened
        assert!(unwind_result.is_err());

        // the connection hasn't been freed yet
        assert_eq!(config.test_get_refcount()?, 2);

        drop(connection);
        assert_eq!(config.test_get_refcount()?, 1);

        Ok(())
    }
}
