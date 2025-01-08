// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    enums::FipsMode,
    error::{Error, Fallible},
};
use s2n_tls_sys::*;
use std::sync::Once;

static S2N_INIT: Once = Once::new();

/// # Safety
///
/// This function should only be called once
unsafe fn global_init() -> Result<(), Error> {
    mem::init()?;
    s2n_init().into_result()?;
    Ok(())
}

thread_local! {
    static S2N_THREAD: Thread = {
        S2N_INIT.call_once(|| unsafe {
            // Safety: by using `Once` we can ensure the library is initialized once
            global_init().expect("could not initialize s2n-tls");
        });
        Thread
    };
}

struct Thread;

impl Drop for Thread {
    fn drop(&mut self) {
        // https://doc.rust-lang.org/std/thread/struct.LocalKey.html#platform-specific-behavior
        // Note that a "best effort" is made to ensure that destructors for types stored in thread local storage are run, but not all platforms can guarantee that destructors will be run for all types in thread local storage.
        let _ = unsafe { s2n_cleanup().into_result() };
    }
}

pub fn init() {
    S2N_THREAD.with(|_| ());
}

/// Determines whether s2n-tls is operating in FIPS mode.
///
/// It is possible to enable FIPS mode by enabling the `fips` feature flag.
///
/// s2n-tls MUST be linked to a FIPS libcrypto and MUST be in FIPS mode in order to comply with
/// FIPS requirements. Applications desiring FIPS compliance should use this API to ensure that
/// s2n-tls has been properly linked with a FIPS libcrypto and has successfully entered FIPS mode.
pub fn fips_mode() -> Result<FipsMode, Error> {
    let mut fips_mode = s2n_fips_mode::FIPS_MODE_DISABLED;
    unsafe {
        s2n_get_fips_mode(&mut fips_mode as *mut _).into_result()?;
    }
    fips_mode.try_into()
}

mod mem {
    use super::*;
    use alloc::alloc::{alloc, dealloc, Layout};
    use core::{ffi::c_void, mem::size_of};

    pub unsafe fn init() -> Result<(), Error> {
        s2n_mem_set_callbacks(
            Some(mem_init_callback),
            Some(mem_cleanup_callback),
            Some(mem_malloc_callback),
            Some(mem_free_callback),
        )
        .into_result()?;
        Ok(())
    }

    unsafe extern "C" fn mem_init_callback() -> s2n_status_code::Type {
        // no-op: the global allocator is already initialized
        s2n_status_code::SUCCESS
    }

    unsafe extern "C" fn mem_cleanup_callback() -> s2n_status_code::Type {
        // no-op: the global allocator is already initialized
        s2n_status_code::SUCCESS
    }

    unsafe extern "C" fn mem_malloc_callback(
        ptr: *mut *mut c_void,
        requested_len: u32,
        allocated_len: *mut u32,
    ) -> s2n_status_code::Type {
        let layout = if let Some(layout) = layout(requested_len) {
            layout
        } else {
            return s2n_status_code::SUCCESS;
        };
        *ptr = alloc(layout) as *mut _;

        if ptr.is_null() {
            s2n_status_code::FAILURE
        } else {
            *allocated_len = requested_len;
            s2n_status_code::SUCCESS
        }
    }

    unsafe extern "C" fn mem_free_callback(ptr: *mut c_void, len: u32) -> s2n_status_code::Type {
        let layout = if let Some(layout) = layout(len) {
            layout
        } else {
            return s2n_status_code::FAILURE;
        };

        if !ptr.is_null() {
            dealloc(ptr as *mut _, layout);
        }

        s2n_status_code::SUCCESS
    }

    unsafe fn layout(len: u32) -> Option<Layout> {
        // https://linux.die.net/man/3/malloc
        //# The malloc() and calloc() functions return a pointer to the
        //# allocated memory, which is suitably aligned for any built-in
        //# type.
        const ALIGNMENT: usize = size_of::<usize>();

        // * align must not be zero,
        //
        // * align must be a power of two,
        //
        // * size, when rounded up to the nearest multiple of align, must not overflow (i.e., the rounded value must be less than or equal to usize::MAX).

        Layout::from_size_align(len as usize, ALIGNMENT).ok()
    }
}
