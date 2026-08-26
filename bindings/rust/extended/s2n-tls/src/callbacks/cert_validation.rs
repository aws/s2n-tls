// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls_sys::*;

use crate::{
    callbacks::ConnectionFuture,
    connection::Connection,
    error::{Error, Fallible},
};
use std::{pin::Pin, ptr::NonNull};

/// The info object provided to a certificate validation callback.
///
/// Used to signal the result of the application's custom validation by calling
/// [`accept`](Self::accept) or [`reject`](Self::reject).
///
/// Corresponds to [`s2n_cert_validation_info`].
///
/// # Safety
///
/// The underlying `s2n_cert_validation_info` is not independently allocated; it
/// is embedded in the [`Connection`] that produced the callback and shares that
/// connection's lifetime. The caller MUST resolve the info before the owning
/// connection is dropped, and MUST NOT resolve it against a different
/// connection. Doing otherwise is undefined behavior.
///
/// In the intended usage the info is moved into the [`ConnectionFuture`]
/// returned from the callback and resolved inside [`ConnectionFuture::poll`],
/// where the owning connection is guaranteed to still be alive.
pub struct CertValidationInfo {
    info: NonNull<s2n_cert_validation_info>,
}

/// # Safety
///
/// s2n_cert_validation_info objects can be sent across threads. This allows an
/// application to hand the info off to a worker thread and call `accept()` or
/// `reject()` once its asynchronous validation completes.
unsafe impl Send for CertValidationInfo {}

/// # Safety
///
/// All C methods that mutate the s2n_cert_validation_info are wrapped in Rust
/// methods that consume the owned info, so it can never be mutated concurrently.
unsafe impl Sync for CertValidationInfo {}

impl CertValidationInfo {
    pub(crate) fn from_ptr(info: *mut s2n_cert_validation_info) -> Self {
        let info = NonNull::new(info).expect("info pointer should not be null");
        CertValidationInfo { info }
    }

    /// Accepts the certificate, allowing the handshake to continue.
    ///
    /// `connection` must be the connection that produced this info; see the
    /// [type-level safety docs](Self).
    ///
    /// Corresponds to [`s2n_cert_validation_accept`].
    pub fn accept(self, _connection: &mut Connection) -> Result<(), Error> {
        unsafe { s2n_cert_validation_accept(self.info.as_ptr()).into_result() }?;
        Ok(())
    }

    /// Rejects the certificate, causing the handshake to fail.
    ///
    /// `connection` must be the connection that produced this info; see the
    /// [type-level safety docs](Self).
    ///
    /// Corresponds to [`s2n_cert_validation_reject`].
    pub fn reject(self, _connection: &mut Connection) -> Result<(), Error> {
        unsafe { s2n_cert_validation_reject(self.info.as_ptr()).into_result() }?;
        Ok(())
    }
}

/// A trait for a synchronous callback to perform additional validation on
/// received certificates.
///
/// Use in conjunction with [`set_cert_validation_callback_sync`].
pub trait CertValidationCallbackSync: 'static + Send + Sync {
    /// Return a boolean to indicate if the certificate chain passed the validation
    fn handle_validation(
        &self,
        connection: &mut Connection,
        validation_info: &mut CertValidationInfo,
    ) -> Result<bool, Error>;
}

/// A trait for an asynchronous callback to perform additional validation on
/// received certificates.
///
/// Use in conjunction with [`set_cert_validation_callback`].
///
/// This is the asynchronous variant of [`CertValidationCallbackSync`]. It allows
/// the application to perform blocking work (such as network or disk IO) off of
/// the handshake thread without blocking it. While the returned
/// [`ConnectionFuture`] is pending, the handshake pauses and other connections
/// can continue to make progress.
pub trait CertValidationCallback: 'static + Send + Sync {
    /// The application can return an `Ok(None)` to resolve the callback
    /// synchronously, or return an `Ok(Some(ConnectionFuture))` if it wants to
    /// run some asynchronous task before resolving the callback.
    ///
    /// In either case, the application MUST take ownership of `validation_info`
    /// and eventually call either [`CertValidationInfo::accept`] or
    /// [`CertValidationInfo::reject`] in order to unblock the handshake.
    /// For synchronous resolution, call `accept()`/`reject()` before returning
    /// `Ok(None)`. For asynchronous resolution, move `validation_info` into the
    /// returned [`ConnectionFuture`] and call `accept()`/`reject()` once the
    /// future resolves, using the connection provided to [`ConnectionFuture::poll`].
    ///
    /// The info MUST be resolved before the owning connection is dropped; see
    /// the [`CertValidationInfo`] safety documentation.
    fn validate_cert(
        &self,
        connection: &mut Connection,
        validation_info: CertValidationInfo,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{connection::Connection, security, testing::*};
    use core::task::Poll;
    use futures_test::task::new_count_waker;

    struct ValidationContext {
        accept: bool,
    }

    struct SyncCallback(Counter);
    impl CertValidationCallbackSync for SyncCallback {
        fn handle_validation(
            &self,
            conn: &mut Connection,
            _info: &mut CertValidationInfo,
        ) -> Result<bool, Error> {
            self.0.increment();
            let context = conn.application_context::<ValidationContext>().unwrap();
            Ok(context.accept)
        }
    }

    #[test]
    fn sync_cert_validation() -> Result<(), Box<dyn std::error::Error>> {
        for accept in [true, false] {
            let counter = Counter::default();
            let callback = SyncCallback(counter.clone());

            let config = {
                let mut config = config_builder(&security::DEFAULT_TLS13)?;
                config.set_cert_validation_callback_sync(callback)?;
                config.build()?
            };

            let mut pair = TestPair::from_config(&config);
            let context = ValidationContext { accept };
            pair.client.set_application_context(context);

            assert_eq!(counter.count(), 0);

            if accept {
                pair.handshake()?;
            } else {
                let s2n_err = pair.handshake().unwrap_err();
                assert_eq!(s2n_err.name(), "S2N_ERR_CERT_REJECTED");
            }

            assert_eq!(counter.count(), 1);
        }

        Ok(())
    }

    /// A future which pends a fixed number of times before resolving the
    /// validation by consuming the owned [`CertValidationInfo`].
    struct AsyncValidationFuture {
        info: Option<CertValidationInfo>,
        remaining_polls: usize,
        accept: bool,
    }

    impl ConnectionFuture for AsyncValidationFuture {
        fn poll(
            mut self: Pin<&mut Self>,
            conn: &mut Connection,
            ctx: &mut core::task::Context,
        ) -> Poll<Result<(), Error>> {
            if self.remaining_polls > 0 {
                self.remaining_polls -= 1;
                // Wake immediately so the future is polled again.
                ctx.waker().wake_by_ref();
                return Poll::Pending;
            }

            let info = self
                .info
                .take()
                .expect("future should not be polled after it resolves");
            let result = if self.accept {
                info.accept(conn)
            } else {
                info.reject(conn)
            };
            Poll::Ready(result)
        }
    }

    struct AsyncValidationCallback {
        counter: Counter,
        poll_count: usize,
    }
    impl CertValidationCallback for AsyncValidationCallback {
        fn validate_cert(
            &self,
            conn: &mut Connection,
            info: CertValidationInfo,
        ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error> {
            self.counter.increment();
            let accept = conn
                .application_context::<ValidationContext>()
                .unwrap()
                .accept;
            let future = AsyncValidationFuture {
                info: Some(info),
                remaining_polls: self.poll_count,
                accept,
            };
            Ok(Some(Box::pin(future)))
        }
    }

    #[test]
    fn async_cert_validation() -> Result<(), Box<dyn std::error::Error>> {
        const POLL_COUNT: usize = 10;

        for accept in [true, false] {
            let counter = Counter::default();
            let callback = AsyncValidationCallback {
                counter: counter.clone(),
                poll_count: POLL_COUNT,
            };

            let config = {
                let mut config = config_builder(&security::DEFAULT_TLS13)?;
                config.set_cert_validation_callback(callback)?;
                config.build()?
            };

            let mut pair = TestPair::from_config(&config);
            // The client validates the server's certificate, so the async
            // callback (and therefore the connection future) runs on the client.
            let (waker, wake_count) = new_count_waker();
            pair.client.set_waker(Some(&waker))?;
            let context = ValidationContext { accept };
            pair.client.set_application_context(context);

            assert_eq!(counter.count(), 0);
            assert_eq!(wake_count, 0);

            if accept {
                pair.handshake()?;
            } else {
                let s2n_err = pair.handshake().unwrap_err();
                assert_eq!(s2n_err.name(), "S2N_ERR_CERT_REJECTED");
            }

            // The callback is invoked exactly once and the future is polled
            // until it resolves the validation.
            assert_eq!(counter.count(), 1);
            assert_eq!(wake_count, POLL_COUNT);
        }

        Ok(())
    }
}
