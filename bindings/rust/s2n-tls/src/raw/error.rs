// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::{fmt, ptr::NonNull};
use libc::c_char;
use s2n_tls_sys::*;
use std::ffi::CStr;

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
            Self::InvalidInput => "A parameter was incorrect.",
            Self::Code(code) => unsafe {
                // Safety: we assume the string has a valid encoding coming from s2n
                cstr_to_str(s2n_strerror(*code, core::ptr::null()))
            },
        }
    }

    pub fn debug(&self) -> &'static str {
        match self {
            Self::InvalidInput => "A parameter was incorrect.",
            Self::Code(code) => unsafe {
                // Safety: we assume the string has a valid encoding coming from s2n
                cstr_to_str(s2n_strerror_debug(*code, core::ptr::null()))
            },
        }
    }

    pub fn kind(&self) -> s2n_error_type::Type {
        match self {
            Self::InvalidInput => s2n_error_type::USAGE,
            Self::Code(code) => unsafe { s2n_error_get_type(*code) as _ },
        }
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
        let alternate = f.alternate();

        let mut s = f.debug_struct("Error");
        if let Self::Code(code) = self {
            s.field("code", code);
        }
        s.field("name", &self.name())
            .field("message", &self.message())
            .field("kind", &self.kind());

        if alternate {
            s.field("debug", &self.debug());
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
