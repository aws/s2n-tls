#![allow(non_camel_case_types)]

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

pub type s2n_result<T = (), E = ()> = core::result::Result<T, E>;

impl Outcome for s2n_result {
    #[inline(always)]
    fn ok() -> Self {
        Ok(())
    }

    #[inline(always)]
    fn is_ok(self) -> bool {
        matches!(self, Ok(_))
    }

    #[inline(always)]
    fn error() -> Self {
        Err(())
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
