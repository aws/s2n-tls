// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::{convert::TryInto, fmt, ptr::NonNull, task::Poll};
use errno::{errno, Errno};
use libc::c_char;
use s2n_tls_sys::*;
use std::{convert::TryFrom, ffi::CStr};

#[non_exhaustive]
#[derive(Debug, PartialEq)]
pub enum ErrorType {
    UnknownErrorType,
    NoError,
    IOError,
    ConnectionClosed,
    Blocked,
    Alert,
    ProtocolError,
    InternalError,
    UsageError,
    Application,
}

#[non_exhaustive]
#[derive(Debug, PartialEq)]
pub enum ErrorSource {
    Library,
    Bindings,
    Application,
}

impl From<libc::c_int> for ErrorType {
    fn from(input: libc::c_int) -> Self {
        match input as s2n_error_type::Type {
            s2n_error_type::OK => ErrorType::NoError,
            s2n_error_type::IO => ErrorType::IOError,
            s2n_error_type::CLOSED => ErrorType::ConnectionClosed,
            s2n_error_type::BLOCKED => ErrorType::Blocked,
            s2n_error_type::ALERT => ErrorType::Alert,
            s2n_error_type::PROTO => ErrorType::ProtocolError,
            s2n_error_type::INTERNAL => ErrorType::InternalError,
            s2n_error_type::USAGE => ErrorType::UsageError,
            _ => ErrorType::UnknownErrorType,
        }
    }
}

enum Context {
    InvalidInput,
    MissingWaker,
    Code(s2n_status_code::Type, Errno),
    Application(Box<dyn std::error::Error + Send + Sync + 'static>),
}

pub struct Error(Context);

pub trait Fallible {
    type Output;

    fn into_result(self) -> Result<Self::Output, Error>;
}

impl Fallible for s2n_status_code::Type {
    type Output = s2n_status_code::Type;

    fn into_result(self) -> Result<Self::Output, Error> {
        if self >= s2n_status_code::SUCCESS {
            Ok(self)
        } else {
            Err(Error::capture())
        }
    }
}

impl Fallible for isize {
    type Output = usize;

    fn into_result(self) -> Result<Self::Output, Error> {
        // Negative values can't be converted to a real size
        // and instead indicate an error.
        self.try_into().map_err(|_| Error::capture())
    }
}

impl Fallible for u64 {
    type Output = Self;

    /// Converts a u64 to a Result by checking for u64::MAX.
    ///
    /// If a method that returns an unsigned int is fallible,
    /// then the -1 error result wraps around to u64::MAX.
    ///
    /// For a u64 to be Fallible, a result of u64::MAX must not be
    /// possible without an error. For example, [`s2n_connection_get_delay`]
    /// can't return u64::MAX as a valid result because
    /// s2n-tls blinding delays are limited to 30s, or a return value of 3^10 ns,
    /// which is significantly less than u64::MAX. [`s2n_connection_get_delay`]
    /// would therefore only return u64::MAX for a -1 error result.
    fn into_result(self) -> Result<Self::Output, Error> {
        if self != Self::MAX {
            Ok(self)
        } else {
            Err(Error::capture())
        }
    }
}

impl<T> Fallible for *mut T {
    type Output = NonNull<T>;

    fn into_result(self) -> Result<Self::Output, Error> {
        if let Some(value) = NonNull::new(self) {
            Ok(value)
        } else {
            Err(Error::capture())
        }
    }
}

impl<T> Fallible for *const T {
    type Output = *const T;

    fn into_result(self) -> Result<Self::Output, Error> {
        if !self.is_null() {
            Ok(self)
        } else {
            Err(Error::capture())
        }
    }
}

pub trait Pollable {
    type Output;

    fn into_poll(self) -> Poll<Result<Self::Output, Error>>;
}

impl<T: Fallible> Pollable for T {
    type Output = T::Output;

    fn into_poll(self) -> Poll<Result<Self::Output, Error>> {
        match self.into_result() {
            Ok(r) => Ok(r).into(),
            Err(err) if err.is_retryable() => Poll::Pending,
            Err(err) => Err(err).into(),
        }
    }
}

impl Error {
    pub(crate) const INVALID_INPUT: Error = Self(Context::InvalidInput);
    pub(crate) const MISSING_WAKER: Error = Self(Context::MissingWaker);

    /// Converts an io::Error into an s2n-tls Error
    pub fn io_error(err: std::io::Error) -> Error {
        let errno = err.raw_os_error().unwrap_or(1);
        errno::set_errno(errno::Errno(errno));
        s2n_status_code::FAILURE.into_result().unwrap_err()
    }

    /// An error occurred while running application code.
    ///
    /// Can be emitted from [`crate::callbacks::ConnectionFuture::poll()`] to indicate
    /// async task failure.
    pub fn application(error: Box<dyn std::error::Error + Send + Sync + 'static>) -> Self {
        Self(Context::Application(error))
    }

    fn capture() -> Self {
        unsafe {
            let s2n_errno = s2n_errno_location();

            let code = *s2n_errno;

            // https://github.com/aws/s2n-tls/blob/main/docs/USAGE-GUIDE.md#error-handling
            //# To avoid possible confusion, s2n_errno should be cleared after processing
            //# an error: s2n_errno = S2N_ERR_T_OK
            *s2n_errno = s2n_error_type::OK as _;

            Self(Context::Code(code, errno()))
        }
    }

    pub fn name(&self) -> &'static str {
        match self.0 {
            Context::InvalidInput => "InvalidInput",
            Context::MissingWaker => "MissingWaker",
            Context::Application(_) => "ApplicationError",
            Context::Code(code, _) => unsafe {
                // Safety: we assume the string has a valid encoding coming from s2n
                cstr_to_str(s2n_strerror_name(code))
            },
        }
    }

    pub fn message(&self) -> &'static str {
        match self.0 {
            Context::InvalidInput => "A parameter was incorrect",
            Context::MissingWaker => {
                "Tried to perform an asynchronous operation without a configured waker"
            }
            Context::Application(_) => "An error occurred while executing application code",
            Context::Code(code, _) => unsafe {
                // Safety: we assume the string has a valid encoding coming from s2n
                cstr_to_str(s2n_strerror(code, core::ptr::null()))
            },
        }
    }

    pub fn debug(&self) -> Option<&'static str> {
        match self.0 {
            Context::InvalidInput | Context::MissingWaker | Context::Application(_) => None,
            Context::Code(code, _) => unsafe {
                let debug_info = s2n_strerror_debug(code, core::ptr::null());

                // The debug string should be set to a constant static string
                // when an error occurs, but because it starts out as NULL
                // we should defend against mistakes.
                if debug_info.is_null() {
                    None
                } else {
                    // If the string is not null, then we can assume that
                    // it is constant and static.
                    Some(cstr_to_str(debug_info))
                }
            },
        }
    }

    pub fn kind(&self) -> ErrorType {
        match self.0 {
            Context::InvalidInput | Context::MissingWaker => ErrorType::UsageError,
            Context::Application(_) => ErrorType::Application,
            Context::Code(code, _) => unsafe { ErrorType::from(s2n_error_get_type(code)) },
        }
    }

    pub fn source(&self) -> ErrorSource {
        match self.0 {
            Context::InvalidInput | Context::MissingWaker => ErrorSource::Bindings,
            Context::Application(_) => ErrorSource::Application,
            Context::Code(_, _) => ErrorSource::Library,
        }
    }

    #[allow(clippy::borrowed_box)]
    /// Returns an [`std::error::Error`] if the error source was [`ErrorSource::Application`],
    /// otherwise returns None.
    pub fn application_error(&self) -> Option<&Box<dyn std::error::Error + Send + Sync + 'static>> {
        if let Self(Context::Application(err)) = self {
            Some(err)
        } else {
            None
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self.kind(), ErrorType::Blocked)
    }
}

#[cfg(feature = "quic")]
impl Error {
    /// s2n-tls does not send specific errors.
    ///
    /// However, we can attempt to map local errors into the alerts
    /// that we would have sent if we sent alerts.
    ///
    /// This API is currently incomplete and should not be relied upon.
    pub fn alert(&self) -> Option<u8> {
        match self.0 {
            Context::InvalidInput | Context::MissingWaker | Context::Application(_) => None,
            Context::Code(code, _) => {
                let mut alert = 0;
                let r = unsafe { s2n_error_get_alert(code, &mut alert) };
                match r.into_result() {
                    Ok(_) => Some(alert),
                    Err(_) => None,
                }
            }
        }
    }
}

/// # Safety
///
/// The caller must ensure the char pointer must contain a valid
/// UTF-8 string from a trusted source
unsafe fn cstr_to_str(v: *const c_char) -> &'static str {
    let slice = CStr::from_ptr(v);
    let bytes = slice.to_bytes();
    core::str::from_utf8_unchecked(bytes)
}

impl TryFrom<std::io::Error> for Error {
    type Error = Error;
    fn try_from(value: std::io::Error) -> Result<Self, Self::Error> {
        let io_inner = value.into_inner().ok_or(Error::INVALID_INPUT)?;
        io_inner
            .downcast::<Self>()
            .map(|error| *error)
            .map_err(|_| Error::INVALID_INPUT)
    }
}

impl From<Error> for std::io::Error {
    fn from(input: Error) -> Self {
        if let Context::Code(_, errno) = input.0 {
            if ErrorType::IOError == input.kind() {
                let bare = std::io::Error::from_raw_os_error(errno.0);
                return std::io::Error::new(bare.kind(), input);
            }
        }
        std::io::Error::new(std::io::ErrorKind::Other, input)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut s = f.debug_struct("Error");
        if let Context::Code(code, _) = self.0 {
            s.field("code", &code);
        }

        s.field("name", &self.name());
        s.field("message", &self.message());
        s.field("kind", &self.kind());
        s.field("source", &self.source());

        if let Some(debug) = self.debug() {
            s.field("debug", &debug);
        }

        // "errno" is only known to be meaningful for IOErrors.
        // However, it has occasionally proved useful for debugging
        // other errors, so include it for all errors.
        if let Context::Code(_, errno) = self.0 {
            s.field("errno", &errno.to_string());
        }

        s.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Self(Context::Application(err)) = self {
            err.fmt(f)
        } else {
            f.write_str(self.message())
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // implement `source` in the same way `std::io::Error` implements it:
        // https://doc.rust-lang.org/std/io/struct.Error.html#method.source
        if let Self(Context::Application(err)) = self {
            err.source()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{enums::Version, testing::client_hello::CustomError};
    use errno::set_errno;

    const FAILURE: isize = -1;

    // This relies on an implementation detail of s2n-tls errors,
    // and could make these tests brittle. However, the alternative
    // is a real handshake producing a real IO error, so just updating
    // this value if the definition of an IO error changes might be easier.
    const S2N_IO_ERROR_CODE: s2n_status_code::Type = 1 << 26;

    #[test]
    fn s2n_io_error_to_std_io_error() -> Result<(), Box<dyn std::error::Error>> {
        set_errno(Errno(libc::ECONNRESET));
        unsafe {
            let s2n_errno_ptr = s2n_errno_location();
            *s2n_errno_ptr = S2N_IO_ERROR_CODE;
        }

        let s2n_error = FAILURE.into_result().unwrap_err();
        assert_eq!(ErrorType::IOError, s2n_error.kind());

        let io_error = std::io::Error::from(s2n_error);
        assert_eq!(std::io::ErrorKind::ConnectionReset, io_error.kind());
        assert!(io_error.into_inner().is_some());
        Ok(())
    }

    #[test]
    fn s2n_error_to_std_io_error() -> Result<(), Box<dyn std::error::Error>> {
        set_errno(Errno(libc::ECONNRESET));
        unsafe {
            let s2n_errno_ptr = s2n_errno_location();
            *s2n_errno_ptr = S2N_IO_ERROR_CODE - 1;
        }

        let s2n_error = FAILURE.into_result().unwrap_err();
        assert_ne!(ErrorType::IOError, s2n_error.kind());

        let io_error = std::io::Error::from(s2n_error);
        assert_eq!(std::io::ErrorKind::Other, io_error.kind());
        assert!(io_error.into_inner().is_some());
        Ok(())
    }

    #[test]
    fn invalid_input_to_std_io_error() -> Result<(), Box<dyn std::error::Error>> {
        let s2n_error = Version::try_from(0).unwrap_err();
        assert_eq!(ErrorType::UsageError, s2n_error.kind());

        let io_error = std::io::Error::from(s2n_error);
        assert_eq!(std::io::ErrorKind::Other, io_error.kind());
        assert!(io_error.into_inner().is_some());
        Ok(())
    }

    #[test]
    fn error_source() -> Result<(), Box<dyn std::error::Error>> {
        let bindings_error = Version::try_from(0).unwrap_err();
        assert_eq!(ErrorSource::Bindings, bindings_error.source());

        let library_error = FAILURE.into_result().unwrap_err();
        assert_eq!(ErrorSource::Library, library_error.source());

        Ok(())
    }

    #[test]
    fn application_error() {
        // test single level errors
        {
            let error = Error::application(Box::new(CustomError));

            let app_error = error.application_error().unwrap();
            let _custom_error = app_error.downcast_ref::<CustomError>().unwrap();
        }

        // make sure nested errors work
        {
            let io_error = std::io::Error::new(std::io::ErrorKind::Other, CustomError);
            let error = Error::application(Box::new(io_error));

            let app_error = error.application_error().unwrap();
            let io_error = app_error.downcast_ref::<std::io::Error>().unwrap();
            let _custom_error = io_error
                .get_ref()
                .unwrap()
                .downcast_ref::<CustomError>()
                .unwrap();
        }
    }
}
