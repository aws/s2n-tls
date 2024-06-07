use crate::ok;
use crate::utils::s2n_result::s2n_result;

pub unsafe fn s2n_rand_cleanup_thread() -> s2n_result {
    ok!()
}

pub unsafe fn s2n_rand_cleanup() -> s2n_result {
    ok!()
}

pub unsafe fn s2n_rand_init() -> s2n_result {
    ok!()
}

pub unsafe fn s2n_get_public_random_data<T>(out: *mut T) -> s2n_result {
    todo!()
}

pub unsafe fn s2n_get_private_random_data<T>(out: *mut T) -> s2n_result {
    todo!()
}

pub unsafe fn s2n_public_random(max: i64, output: *mut u64) -> s2n_result {
    todo!()
}
