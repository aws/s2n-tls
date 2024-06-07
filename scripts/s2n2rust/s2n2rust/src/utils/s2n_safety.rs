use crate::utils::s2n_result::s2n_result;
use core::hint::black_box;
use libc::c_int;

#[inline(always)]
pub fn implies(a: bool, b: bool) -> bool {
    !a || b
}

#[inline(always)]
pub fn iff(a: bool, b: bool) -> bool {
    a == b
}

#[macro_export]
macro_rules! ok {
    () => {
        $crate::utils::s2n_result::Outcome::ok()
    };
}

#[macro_export]
macro_rules! error {
    () => {
        $crate::utils::s2n_result::Outcome::error()
    };
    ($code:expr $(,)?) => {{
        $crate::error::s2n_errno::set!($code);
        return $crate::error!();
    }};
}

#[macro_export]
macro_rules! ensure_ref {
    ($value:expr $(,)?) => {
        if $value.is_null() {
            $crate::error!(S2N_ERR_NULL);
        }
    };
}

#[macro_export]
macro_rules! ensure {
    ($cond:expr, $code:expr $(,)?) => {
        if !$cond {
            $crate::error!($code);
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
        if !$crate::utils::s2n_result::Outcome::is_ok($expr) {
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
pub unsafe fn memmove<T, L>(dest: *mut T, src: *const T, len: L) -> s2n_result
where
    L: TryInto<usize>,
{
    ensure_ref!(dest);
    ensure_ref!(src);
    let Ok(len) = len.try_into() else {
        error!(S2N_ERR_SAFETY);
    };
    core::ptr::copy(src, dest, len);
    ok!()
}

#[inline(always)]
pub unsafe fn memcmp<T, L>(a: *const T, b: *const T, len: L) -> c_int
where
    L: TryInto<usize>,
{
    ensure_ref!(a);
    ensure_ref!(a);
    let Ok(len) = len.try_into() else {
        error!(S2N_ERR_SAFETY);
    };
    libc::memcmp(a as *const _, b as *const _, len)
}

pub unsafe fn s2n_in_unit_test_set(is_unit: bool) -> c_int {
    // TODO
    ok!()
}

pub unsafe fn s2n_in_integ_test_set(is_unit: bool) -> c_int {
    // TODO
    ok!()
}

#[inline(always)]
pub unsafe fn s2n_in_unit_test() -> bool {
    false
}

#[inline(always)]
pub fn s2n_in_test() -> bool {
    false
}

#[inline(always)]
pub unsafe fn s2n_align_to(initial: u32, alignment: u32, out: *mut u32) -> s2n_result {
    ensure_ref!(out);
    ensure!(alignment != 0, S2N_ERR_SAFETY);

    if initial == 0 {
        *out = 0;
        return ok!();
    }

    let i = initial as u64;
    let a = alignment as u64;

    let result = a * (((i - 1) / a) + 1);
    if let Ok(result) = result.try_into() {
        *out = result;
    } else {
        error!(S2N_ERR_INTEGER_OVERFLOW);
    }

    ok!()
}

#[inline(always)]
pub unsafe fn s2n_mul_overflow(a: u32, b: u32, out: *mut u32) -> s2n_result {
    ensure_ref!(out);
    if let Some(res) = a.checked_mul(b) {
        *out = res;
    } else {
        error!(S2N_ERR_INTEGER_OVERFLOW);
    }
    ok!()
}

#[inline(always)]
pub unsafe fn s2n_add_overflow(a: u32, b: u32, out: *mut u32) -> s2n_result {
    ensure_ref!(out);
    if let Some(res) = a.checked_add(b) {
        *out = res;
    } else {
        error!(S2N_ERR_INTEGER_OVERFLOW);
    }
    ok!()
}

#[inline(always)]
pub unsafe fn s2n_sub_overflow(a: u32, b: u32, out: *mut u32) -> s2n_result {
    ensure_ref!(out);
    if let Some(res) = a.checked_sub(b) {
        *out = res;
    } else {
        error!(S2N_ERR_INTEGER_OVERFLOW);
    }
    ok!()
}

#[inline(never)]
pub unsafe extern "C" fn s2n_constant_time_equals(a: *const u8, b: *const u8, len: u32) -> bool {
    if len == 0 {
        return true;
    }

    let standin = 0u8;

    let a = CtPtr::new(a, &standin);
    let b = CtPtr::new(b, &standin);

    let xor = black_box(a.cmp(&b, len));

    xor == 0
}

struct CtPtr {
    v: *const u8,
    ptr_mask: isize,
}

impl CtPtr {
    fn new(v: *const u8, standin: *const u8) -> Self {
        if black_box(v.is_null()) {
            Self {
                v: standin,
                ptr_mask: 0,
            }
        } else {
            Self {
                v,
                ptr_mask: isize::MAX,
            }
        }
    }

    fn value_mask(&self) -> u8 {
        !(self.ptr_mask as u8)
    }

    unsafe fn offset(&self, offset: isize) -> *const u8 {
        self.v.offset(offset & self.ptr_mask)
    }

    fn read(&self, offset: isize) -> u8 {
        unsafe { *self.offset(offset) }
    }

    fn cmp(&self, other: &Self, len: u32) -> u8 {
        let mut xor = self.value_mask() | other.value_mask();

        let len = len as isize;

        for offset in 0..len {
            xor |= self.read(offset) ^ other.read(offset);
        }

        xor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, bolero::TypeGenerator)]
    struct Input {
        a: Vec<u8>,
        a_valid: bool,
        b: Vec<u8>,
        b_valid: bool,
    }

    impl Input {
        fn len(&self) -> usize {
            self.a.len().min(self.b.len())
        }

        fn check(&self) {
            assert_eq!(self.subject(), self.oracle())
        }

        fn subject(&self) -> bool {
            let len = self.len() as u32;
            unsafe { s2n_constant_time_equals(self.a(), self.b(), len) }
        }

        fn oracle(&self) -> bool {
            if self.len() == 0 {
                return true;
            }

            if self.a_valid && self.b_valid {
                let len = self.len();
                self.a[..len].eq(&self.b[..len])
            } else {
                false
            }
        }

        fn a(&self) -> *const u8 {
            if self.a_valid {
                self.a.as_ptr()
            } else {
                core::ptr::null()
            }
        }

        fn b(&self) -> *const u8 {
            if self.b_valid {
                self.b.as_ptr()
            } else {
                core::ptr::null()
            }
        }
    }

    #[test]
    fn ct_eq() {
        bolero::check!().with_type::<Input>().for_each(|input| {
            input.check();
        })
    }
}
