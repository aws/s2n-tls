// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls_sys::*;

use crate::{
    callbacks::*,
    connection::Connection,
    error::{Error, Fallible},
};
use std::{pin::Pin, ptr::NonNull};

pub struct CertValidationInfo {
    info: NonNull<s2n_cert_validation_info>,
}

/// # Safety
///
/// Safety: s2n_cert_validation_info objects can be sent across threads
unsafe impl Send for CertValidationInfo {}

/// # Safety
///
/// Safety: All C methods that mutate the s2n_cert_validation_info are wrapped
/// in Rust methods that require a mutable reference.
unsafe impl Sync for CertValidationInfo {}

impl CertValidationInfo {
    pub(crate) fn from_ptr(info: *mut s2n_cert_validation_info) -> Result<Self, Error> {
        let info = NonNull::new(info).ok_or(Error::INVALID_INPUT)?;
        Ok(CertValidationInfo { info })
    }

    pub(crate) fn as_ptr(&self) -> *mut s2n_cert_validation_info {
        self.info.as_ptr()
    }

    /// Corresponds to [s2n_cert_validation_accept].
    pub fn accept(self) -> Result<(), Error> {
        unsafe { s2n_cert_validation_accept(self.as_ptr()).into_result() }?;
        Ok(())
    }

    /// Corresponds to [s2n_cert_validation_reject].
    pub fn reject(self) -> Result<(), Error> {
        unsafe { s2n_cert_validation_reject(self.as_ptr()).into_result() }?;
        Ok(())
    }
}

pub trait CertValidationCallback: 'static + Send + Sync {
    fn handle_validation(
        &self,
        connection: &mut Connection,
        validation_info: CertValidationInfo,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{connection::Connection, error, security, testing::*};
    use core::task::Poll;
    use futures_test::task::new_count_waker;

    type Error = Box<dyn std::error::Error>;

    struct ValidationContext {
        accept: bool,
    }

    struct SyncCallback(Counter);
    impl CertValidationCallback for SyncCallback {
        fn handle_validation(
            &self,
            conn: &mut Connection,
            info: CertValidationInfo,
        ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, error::Error> {
            self.0.increment();
            let context = conn.application_context::<ValidationContext>().unwrap();

            match context.accept {
                true => info.accept()?,
                false => info.reject()?,
            }
            Ok(None)
        }
    }

    #[test]
    fn sync_cert_validation() -> Result<(), Error> {
        for accept in [true, false] {
            let counter = Counter::default();
            let callback = SyncCallback(counter.clone());

            let config = {
                let mut config = config_builder(&security::DEFAULT_TLS13)?;
                config.set_cert_validation_callback(callback)?;
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

    const POLL_COUNT: usize = 10;

    struct AsyncFuture {
        counter: usize,
        info: Option<CertValidationInfo>,
    }
    impl ConnectionFuture for AsyncFuture {
        fn poll(
            mut self: Pin<&mut Self>,
            conn: &mut Connection,
            _ctx: &mut core::task::Context,
        ) -> Poll<Result<(), error::Error>> {
            conn.waker().unwrap().wake_by_ref();
            self.counter += 1;
            let context = conn.application_context::<ValidationContext>().unwrap();

            if self.counter < POLL_COUNT {
                Poll::Pending
            } else if let Some(info) = self.info.take() {
                match context.accept {
                    true => Poll::Ready(info.accept()),
                    false => Poll::Ready(info.reject()),
                }
            } else {
                Poll::Ready(Err(error::Error::application(
                    "missing validation info".into(),
                )))
            }
        }
    }

    struct AsyncCallback(Counter);
    impl CertValidationCallback for AsyncCallback {
        fn handle_validation(
            &self,
            _conn: &mut Connection,
            info: CertValidationInfo,
        ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, error::Error> {
            self.0.increment();
            let future = AsyncFuture {
                counter: 0,
                info: Some(info),
            };
            Ok(Some(Box::pin(future)))
        }
    }

    #[test]
    fn async_cert_validation() -> Result<(), Error> {
        for accept in [true, false] {
            let counter = Counter::default();
            let callback = AsyncCallback(counter.clone());

            let config = {
                let mut config = config_builder(&security::DEFAULT_TLS13)?;
                config.set_cert_validation_callback(callback)?;
                config.build()?
            };

            let (waker, wake_count) = new_count_waker();
            let mut pair = TestPair::from_config(&config);
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

            assert_eq!(counter.count(), 1);
            assert_eq!(wake_count, POLL_COUNT);
        }

        Ok(())
    }
}
