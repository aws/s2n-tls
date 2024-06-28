use crate::replace::Overrides;
use crate::Result;

#[allow(dead_code)]
pub mod s2n_errno;

/// get enough errors to have the script compile - the rest will be generated with bindgen
#[allow(dead_code)]
pub mod s2n_errno_errors {
    use core::ffi::c_int;
    pub const S2N_ERR_SAFETY: c_int = 1;
    pub const S2N_ERR_NULL: c_int = 1;
    pub const S2N_ERR_INTEGER_OVERFLOW: c_int = 1;
}

pub fn run(o: &mut Overrides) -> Result {
    o.write("error/s2n_errno.rs", include_str!("./error/s2n_errno.rs"))?;
    Ok(())
}
