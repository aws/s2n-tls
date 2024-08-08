use core::cmp::Ordering;
use libc::c_int;

macro_rules! impl_cmp {
    ($ty:ident, $other:ident) => {
        impl PartialEq<$other> for $ty {
            #[inline]
            fn eq(&self, other: &$other) -> bool {
                self.partial_cmp(other) == Some(Ordering::Equal)
            }
        }

        impl PartialOrd<$other> for $ty {
            #[inline]
            fn partial_cmp(&self, other: &$other) -> Option<Ordering> {
                Some((*self as i32).cmp(&(*other as i32)))
            }
        }

        impl PartialEq<$ty> for $other {
            #[inline]
            fn eq(&self, other: &$ty) -> bool {
                other.eq(self)
            }
        }

        impl PartialOrd<$ty> for $other {
            #[inline]
            fn partial_cmp(&self, other: &$ty) -> Option<Ordering> {
                other.partial_cmp(self)
            }
        }
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum TlsVersion {
    SSLv2 = 20,
    SSLv3 = 30,
    TLS10 = 31,
    TLS11 = 32,
    TLS12 = 33,
    TLS13 = 34,
}

impl_cmp!(TlsVersion, c_int);

pub const S2N_SSLv2: TlsVersion = TlsVersion::SSLv2;
pub const S2N_SSLv3: TlsVersion = TlsVersion::SSLv3;
pub const S2N_TLS10: TlsVersion = TlsVersion::TLS10;
pub const S2N_TLS11: TlsVersion = TlsVersion::TLS11;
pub const S2N_TLS12: TlsVersion = TlsVersion::TLS12;
pub const S2N_TLS13: TlsVersion = TlsVersion::TLS13;
