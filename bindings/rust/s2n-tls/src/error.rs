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

#[derive(PartialEq)]
pub enum Error {
    InvalidInput,
    Code(s2n_status_code::Type, Errno),
}

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
    pub fn new<T: Fallible>(value: T) -> Result<T::Output, Self> {
        value.into_result()
    }

    fn capture() -> Self {
        unsafe {
            let s2n_errno = s2n_errno_location();

            let code = *s2n_errno;

            // https://github.com/aws/s2n-tls/blob/main/docs/USAGE-GUIDE.md#error-handling
            //# To avoid possible confusion, s2n_errno should be cleared after processing
            //# an error: s2n_errno = S2N_ERR_T_OK
            *s2n_errno = s2n_error_type::OK as _;

            Self::Code(code, errno())
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::InvalidInput => "InvalidInput",
            Self::Code(code, _) => unsafe {
                // Safety: we assume the string has a valid encoding coming from s2n
                cstr_to_str(s2n_strerror_name(*code))
            },
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::InvalidInput => "A parameter was incorrect",
            Self::Code(code, _) => unsafe {
                // Safety: we assume the string has a valid encoding coming from s2n
                cstr_to_str(s2n_strerror(*code, core::ptr::null()))
            },
        }
    }

    pub fn debug(&self) -> Option<&'static str> {
        match self {
            Self::InvalidInput => None,
            Self::Code(code, _) => unsafe {
                let debug_info = s2n_strerror_debug(*code, core::ptr::null());

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

    pub fn kind(&self) -> Option<ErrorType> {
        match self {
            Self::InvalidInput => None,
            Self::Code(code, _) => unsafe { Some(ErrorType::from(s2n_error_get_type(*code))) },
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self.kind(), Some(ErrorType::Blocked))
    }

    pub fn alert(&self) -> Option<u8> {
        match self {
            Self::InvalidInput => None,
            Self::Code(_, _) => {
                None
                // TODO: We should use the new s2n-tls method
                //       once it's available.
                // let mut alert = 0;
                // match call!(s2n_error_get_alert(*code, &mut alert)) {
                //     Ok(_) => Some(alert),
                //     Err(_) => None,
                // }
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
        let io_inner = value.into_inner().ok_or(Error::InvalidInput)?;
        io_inner
            .downcast::<Self>()
            .map(|error| *error)
            .map_err(|_| Error::InvalidInput)
    }
}

impl From<Error> for std::io::Error {
    fn from(input: Error) -> Self {
        if let Error::Code(_, errno) = input {
            if Some(ErrorType::IOError) == input.kind() {
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
        if let Self::Code(code, _) = self {
            s.field("code", code);
        }

        s.field("name", &self.name());
        s.field("message", &self.message());

        if let Some(kind) = self.kind() {
            s.field("kind", &kind);
        }

        if let Some(debug) = self.debug() {
            s.field("debug", &debug);
        }

        // "errno" is only known to be meaningful for IOErrors.
        // However, it has occasionally proved useful for debugging
        // other errors, so include it for all errors.
        if let Self::Code(_, errno) = self {
            s.field("errno", &errno.to_string());
        }

        s.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use errno::set_errno;

    #[test]
    fn to_io_error() -> Result<(), Box<dyn std::error::Error>> {
        // This relies on an implementation detail of s2n-tls errors,
        // and could make this test brittle. However, the alternative
        // is a real handshake producing a real IO error, so just updating
        // this test if the definition of an IO error changes might be easier.
        let s2n_io_error_code = 1 << 26;
        let s2n_io_error = Error::Code(s2n_io_error_code, Errno(0));
        assert_eq!(Some(ErrorType::IOError), s2n_io_error.kind());

        // IO error
        {
            let s2n_error = Error::Code(s2n_io_error_code, Errno(libc::EACCES));
            let io_error = std::io::Error::from(s2n_error);
            assert_eq!(std::io::ErrorKind::PermissionDenied, io_error.kind());
            assert!(io_error.into_inner().is_some());
        }

        // Captured IO error
        {
            let result: isize = -1;
            set_errno(Errno(libc::ECONNRESET));
            unsafe {
                let s2n_errno_ptr = s2n_errno_location();
                *s2n_errno_ptr = s2n_io_error_code;
            }

            let s2n_error = result.into_result().unwrap_err();
            let io_error = std::io::Error::from(s2n_error);
            assert_eq!(std::io::ErrorKind::ConnectionReset, io_error.kind());
            assert!(io_error.into_inner().is_some());
        }

        // Not IO error
        {
            let s2n_error = Error::Code(s2n_io_error_code - 1, Errno(libc::ECONNRESET));
            let io_error = std::io::Error::from(s2n_error);
            assert_eq!(std::io::ErrorKind::Other, io_error.kind());
            assert!(io_error.into_inner().is_some());
        }

        // Not s2n-tls error
        {
            let s2n_error = Error::InvalidInput;
            let io_error = std::io::Error::from(s2n_error);
            assert_eq!(std::io::ErrorKind::Other, io_error.kind());
            assert!(io_error.into_inner().is_some());
        }

        Ok(())
    }
}
