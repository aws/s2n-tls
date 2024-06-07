use core::cell::Cell;
use core::ffi::{c_int, CStr};
use std::thread_local;

thread_local! {
    static DEBUG_INFO: Cell<s2n_debug_info> = Cell::new(s2n_debug_info::EMPTY);
    static ERRNO: Cell<c_int> = Cell::new(0);
}

#[derive(Clone, Copy, Debug)]
pub struct s2n_debug_info {
    pub(crate) debug_str: &'static CStr,
    pub(crate) source: &'static CStr,
}

impl s2n_debug_info {
    pub const EMPTY: Self = Self {
        debug_str: c"",
        source: c"",
    };

    #[inline]
    pub fn set(self) {
        DEBUG_INFO.with(|d| d.set(self))
    }

    #[inline]
    pub fn get() -> Self {
        DEBUG_INFO.with(|d| d.get())
    }
}

#[inline(always)]
pub fn set(errno: c_int) {
    ERRNO.with(|v| v.set(errno))
}

#[inline(always)]
pub fn get() -> c_int {
    ERRNO.with(|v| v.get())
}

#[inline(always)]
pub fn s2n_error_get_type(errno: c_int) -> c_int {
    todo!()
}

#[inline(always)]
pub fn is_blocking(errno: c_int) -> bool {
    todo!()
}

#[inline(always)]
pub unsafe fn s2n_stack_traces_enabled_set(enabled: bool) {
    todo!()
}

#[macro_export]
#[doc(hidden)]
macro_rules! __s2n_errno_set {
    ($code:expr) => {
        unsafe {
            static DEBUG_INFO: &str = concat!(
                "Error encountered in ",
                file!(),
                ":",
                stringify!(line!()),
                "\0"
            );

            $crate::error::s2n_errno::set({
                #[allow(unused_imports)]
                use $crate::error::s2n_errno_errors::*;
                $code
            });

            $crate::error::s2n_errno::s2n_debug_info {
                debug_str: core::ffi::CStr::from_ptr(DEBUG_INFO.as_ptr() as *const _),
                source: core::ffi::CStr::from_ptr(
                    DEBUG_INFO.rsplit_once('/').unwrap().1.as_ptr() as *const _
                ),
            }
            .set();
        }
    };
}

pub use crate::__s2n_errno_set as set;
