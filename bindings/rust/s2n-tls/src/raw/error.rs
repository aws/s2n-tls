// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::{fmt, ptr::NonNull};
use libc::c_char;
use s2n_tls_sys::*;
use std::ffi::CStr;

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
    Code(s2n_status_code::Type),
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

            Self::Code(code)
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::InvalidInput => "InvalidInput",
            Self::Code(code) => unsafe {
                // Safety: we assume the string has a valid encoding coming from s2n
                cstr_to_str(s2n_strerror_name(*code))
            },
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::InvalidInput => "A parameter was incorrect",
            Self::Code(code) => unsafe {
                // Safety: we assume the string has a valid encoding coming from s2n
                cstr_to_str(s2n_strerror(*code, core::ptr::null()))
            },
        }
    }

    pub fn debug(&self) -> Option<&'static str> {
        match self {
            Self::InvalidInput => None,
            Self::Code(code) => unsafe {
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
            Self::Code(code) => unsafe { Some(ErrorType::from(s2n_error_get_type(*code))) },
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self.kind(), Some(ErrorType::Blocked))
    }

    pub fn alert(&self) -> Option<u8> {
        match self {
            Self::InvalidInput => None,
            Self::Code(_code) => {
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

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut s = f.debug_struct("Error");
        if let Self::Code(code) = self {
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

        s.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for Error {}
