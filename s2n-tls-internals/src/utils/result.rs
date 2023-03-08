use crate::api::s2n::{S2N_FAILURE, S2N_SUCCESS};

/*
 * The goal of s2n_result is to provide a strongly-typed error
 * signal value, which provides the compiler with enough information
 * to catch bugs.
 *
 * Historically, s2n has used int to signal errors. This has caused a few issues:
 *
 * ## GUARD in a function returning integer types
 *
 * There is no compiler error if `GUARD(nested_call());` is used in a function
 * that is meant to return integer type - not a error signal.
 *
 * ```c
 * uint8_t s2n_answer_to_the_ultimate_question() {
 *   POSIX_GUARD(s2n_sleep_for_years(7500000));
 *   return 42;
 * }
 * ```
 *
 * In this function we intended to return a `uint8_t` but used a
 * `GUARD` which will return -1 if the call fails. This can lead to
 * very subtle bugs.
 *
 * ## `GUARD`ing a function returning any integer type
 *
 * There is no compiler error if `GUARD(nested_call());` is used
 * on a function that doesn't actually return an error signal
 *
 * ```c
 * int s2n_deep_thought() {
 *   POSIX_GUARD(s2n_answer_to_the_ultimate_question());
 *   return 0;
 * }
 * ```
 *
 * In this function we intended guard against a failure of
 * `s2n_answer_to_the_ultimate_question` but that function doesn't
 * actually return an error signal. Again, this can lead to sublte
 * bugs.
 *
 * ## Ignored error signals
 *
 * Without the `warn_unused_result` function attribute, the compiler
 * provides no warning when forgetting to `GUARD` a function. Missing
 * a `GUARD` can lead to subtle bugs.
 *
 * ```c
 * int s2n_answer_to_the_ultimate_question() {
 *   s2n_sleep_for_years(7500000); // <- THIS SHOULD BE GUARDED!!!
 *   return 42;
 * }
 * ```
 *
 * # Solution
 *
 * s2n_result provides a newtype declaration, which is popular in
 * languages like [Haskell](https://wiki.haskell.org/Newtype) and
 * [Rust](https://doc.rust-lang.org/rust-by-example/generics/new_types.html).
 *
 * Functions that return S2N_RESULT are automatically marked with the
 * `warn_unused_result` attribute, which ensures they are GUARDed.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct s2n_result {
    __error_signal: ::std::os::raw::c_int,
}

#[test]
fn bindgen_test_layout_s2n_result() {
    const UNINIT: ::std::mem::MaybeUninit<s2n_result> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<s2n_result>(),
        4usize,
        concat!("Size of: ", stringify!(s2n_result))
    );
    assert_eq!(
        ::std::mem::align_of::<s2n_result>(),
        4usize,
        concat!("Alignment of ", stringify!(s2n_result))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).__error_signal) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(s2n_result),
            "::",
            stringify!(__error_signal)
        )
    );
}

#[no_mangle]
pub extern "C" fn s2n_result_is_ok(result: s2n_result) -> bool {
    result.is_ok()
}

#[no_mangle]
pub extern "C" fn s2n_result_is_error(result: s2n_result) -> bool {
    result.is_error()
}

#[no_mangle]
#[doc = " Ignores the returned result of a function\n\n Generally, function results should always be checked. Using this function\n could cause the system to behave in unexpected ways. As such, this function\n should only be used in scenarios where the system state is not affected by\n errors."]
pub extern "C" fn s2n_result_ignore(result: s2n_result) {
    result.ignore()
}

impl s2n_result {
    pub fn validate(self: Self) {
        assert!(self.__error_signal == S2N_FAILURE || self.__error_signal == S2N_SUCCESS);
    }

    pub fn as_result(self: Self) -> Result<(), ()> {
        self.validate();
        match self.__error_signal {
            S2N_SUCCESS => Ok(()),
            S2N_FAILURE => Err(()),
            _ => unreachable!("__error_signal should be either S2N_SUCCESS or S2N_FAILURE."),
        }
    }

    #[must_use]
    pub fn is_ok(self: Self) -> bool {
        self.validate();
        self.__error_signal == S2N_SUCCESS
    }

    #[must_use]
    pub fn is_error(self: Self) -> bool {
        self.validate();
        self.__error_signal == S2N_FAILURE
    }

    pub fn ignore(self: Self) {
        self.validate();
    }
}

#[test]
fn s2n_result_functions() {
    let success = s2n_result {
        __error_signal: S2N_SUCCESS,
    };
    let fail = s2n_result {
        __error_signal: S2N_FAILURE,
    };
    assert!(success.is_error() == false);
    assert!(success.is_ok() == true);
    assert!(fail.is_error() == true);
    assert!(fail.is_ok() == false);
    assert!(success.as_result() == Ok(()));
    assert!(fail.as_result() == Err(()));
}

#[test]
#[should_panic]
fn s2n_result_invalid_value() {
    let invalid_value = s2n_result { __error_signal: 10 };
    invalid_value.validate();
}
