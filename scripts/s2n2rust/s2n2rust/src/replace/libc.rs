use crate::ensure_ref;
pub use ::libc::*;

#[inline(always)]
pub unsafe fn memset<L>(ptr: *mut c_void, value: c_int, len: L)
where
    L: TryInto<usize>,
{
    let len = len.try_into().unwrap_or(usize::MAX);
    ::libc::memset(ptr, value, len);
}

#[inline(always)]
pub unsafe fn memcmp<T, L>(a: *const T, b: *const T, len: L) -> c_int
where
    L: TryInto<usize>,
{
    ensure_ref!(a);
    ensure_ref!(a);
    let Ok(len) = len.try_into() else {
        crate::error!(S2N_ERR_SAFETY);
    };
    ::libc::memcmp(a as *const _, b as *const _, len)
}

#[inline(always)]
pub unsafe fn malloc<L>(len: L) -> *mut c_void
where
    L: TryInto<usize>,
{
    let Ok(len) = len.try_into() else {
        crate::error!(S2N_ERR_SAFETY);
    };
    ::libc::malloc(len)
}

#[inline(always)]
pub unsafe fn strncasecmp<L>(s1: *const c_char, s2: *const c_char, n: L) -> c_int
where
    L: TryInto<usize>,
{
    let Ok(len) = n.try_into() else {
        crate::error!(S2N_ERR_SAFETY);
    };
    ::libc::strncasecmp(s1, s2, len)
}

#[inline(always)]
pub unsafe fn strncmp<L>(cs: *const c_char, ct: *const c_char, n: L) -> c_int
where
    L: TryInto<usize>,
{
    let Ok(len) = n.try_into() else {
        crate::error!(S2N_ERR_SAFETY);
    };
    ::libc::strncmp(cs, ct, len)
}

#[inline(always)]
pub unsafe fn atexit(f: Option<unsafe extern "C" fn()>) -> c_int {
    ::libc::atexit(core::mem::transmute(f))
}
