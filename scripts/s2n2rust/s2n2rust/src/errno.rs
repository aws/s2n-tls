#![allow(non_camel_case_types)]

use core::ffi::c_int;

pub trait Outcome: Sized {
    fn ok() -> Self;
    fn error() -> Self;
    fn is_ok(self) -> bool;
    #[inline(always)]
    fn is_error(self) -> bool {
        !self.is_ok()
    }
}

macro_rules! impl_int {
    ($ty:ty) => {
        impl Outcome for $ty {
            #[inline(always)]
            fn ok() -> Self {
                0
            }

            #[inline(always)]
            fn is_ok(self) -> bool {
                self == 0
            }

            #[inline(always)]
            fn error() -> Self {
                -1
            }
        }
    };
}

impl_int!(i8);
impl_int!(i16);
impl_int!(i32);
impl_int!(i64);
impl_int!(isize);

pub struct s2n_result {
    value: c_int,
}

impl Outcome for s2n_result {
    #[inline(always)]
    fn ok() -> Self {
        Self {
            value: Outcome::ok(),
        }
    }

    #[inline(always)]
    fn is_ok(self) -> bool {
        self.value.is_ok()
    }

    #[inline(always)]
    fn error() -> Self {
        Self {
            value: Outcome::error(),
        }
    }
}

impl<T> Outcome for *const T {
    #[inline(always)]
    fn ok() -> Self {
        unreachable!()
    }

    #[inline(always)]
    fn is_ok(self) -> bool {
        !self.is_null()
    }

    #[inline(always)]
    fn error() -> Self {
        core::ptr::null()
    }
}

impl<T> Outcome for *mut T {
    #[inline(always)]
    fn ok() -> Self {
        unreachable!()
    }

    #[inline(always)]
    fn is_ok(self) -> bool {
        !self.is_null()
    }

    #[inline(always)]
    fn error() -> Self {
        core::ptr::null_mut()
    }
}

#[macro_export]
macro_rules! ok {
    () => {
        $crate::errno::Outcome::ok()
    };
}

#[macro_export]
macro_rules! error {
    () => {
        $crate::errno::Outcome::error()
    };
    ($code:expr $(,)?) => {{
        // TODO set code
        $crate::error!()
    }};
}

#[macro_export]
macro_rules! ensure_ref {
    ($value:expr $(,)?) => {
        if $value.is_null() {
            return $crate::error!(S2N_ERR_NULL);
        }
    };
}

#[macro_export]
macro_rules! ensure {
    ($cond:expr, $code:expr $(,)?) => {
        if !$cond {
            return $crate::error!($code);
        }
    };
}

#[macro_export]
macro_rules! ensure_dbg {
    ($cond:expr, $code:expr $(,)?) => {
        if cfg!(debug_assertions) {
            $crate::ensure!($cond, $code)
        }
    };
}

#[macro_export]
macro_rules! error_if {
    ($cond:expr, $code:expr $(,)?) => {
        $crate::ensure!(!$cond, $code)
    };
}

#[macro_export]
macro_rules! guard_ossl {
    ($cond:expr, $code:expr $(,)?) => {
        if $cond <= 0 {
            return $crate::error!($code);
        }
    };
}

#[macro_export]
macro_rules! guard {
    ($expr:expr $(,)?) => {
        if !$crate::errno::Outcome::is_ok($expr) {
            return $crate::error!();
        }
    };
}

#[macro_export]
macro_rules! precondition {
    ($expr:expr $(,)?) => {
        $crate::guard!($expr)
    };
}

#[macro_export]
macro_rules! postcondition {
    ($expr:expr $(,)?) => {
        if cfg!(debug_assertions) {
            $crate::guard!($expr)
        }
    };
}

#[macro_export]
macro_rules! likely {
    ($cond:expr) => {
        $cond
    };
}

#[macro_export]
macro_rules! unlikely {
    ($cond:expr) => {
        $cond
    };
}

#[inline(always)]
pub unsafe fn memmove<T>(dest: *mut T, src: *const T, len: core::ffi::c_ulong) -> s2n_result {
    ensure_ref!(dest);
    ensure_ref!(src);
    core::ptr::copy(src, dest, len as _);
    ok!()
}

#[inline(always)]
pub fn implies(a: bool, b: bool) -> bool {
    !a || b
}

#[inline(always)]
pub fn iff(a: bool, b: bool) -> bool {
    a == b
}
