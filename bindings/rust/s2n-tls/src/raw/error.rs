// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::fmt;
use libc::{c_char, c_int};
use s2n_tls_sys::*;
use std::ffi::CStr;

// Ensures errors are converted
#[macro_export]
macro_rules! call {
    ($expr:expr) => {{
        #[allow(unused_unsafe)]
        $crate::raw::error::Error::new(unsafe { $expr })
    }};
}

pub enum Error {
    InvalidInput,
    Code(c_int),
}

pub trait Fallible {
    fn is_err(&self) -> bool;
}

impl Fallible for c_int {
    fn is_err(&self) -> bool {
        (*self) < 0
    }
}

impl<T> Fallible for *mut T {
    fn is_err(&self) -> bool {
        <*mut T>::is_null(*self)
    }
}

impl<T> Fallible for *const T {
    fn is_err(&self) -> bool {
        <*const T>::is_null(*self)
    }
}

impl Error {
    pub fn new<T: Fallible>(value: T) -> Result<T, Self> {
        if value.is_err() {
            Err(Self::capture())
        } else {
            Ok(value)
        }
    }

    fn capture() -> Self {
        unsafe {
            let s2n_errno = s2n_errno_location();

            let code = *s2n_errno;

            // https://github.com/awslabs/s2n/blob/main/docs/USAGE-GUIDE.md#error-handling
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
