use s2n_tls_sys::*;

#[test]
fn s2n_init_test() {
    unsafe {
        // don't force the tests to use mlock
        std::env::set_var("S2N_DONT_MLOCK", "1");

        // try to initialize the library
        s2n_init();

        // make sure it was successful
        let error = *s2n_errno_location();
        if error != 0 {
            let msg = s2n_strerror_name(error);
            let msg = std::ffi::CStr::from_ptr(msg);
            panic!("s2n did not initialize correctly: {:?}", msg);
        }
    }
}
