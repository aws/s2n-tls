// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// let the rust compiler that s2n-tls needs to be linked for any of these bindings
// to work
use s2n_tls_sys as _;
use aws_lc_sys as _;

// Include the bindgen generated bindings
#[allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    clippy::all
)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

// Re-export bindings that we need
pub use bindings::{
    s2n_cipher_preferences, s2n_cipher_suite, s2n_ecc_named_curve, s2n_ecc_preferences,
    s2n_kem_group, s2n_kem_preferences, s2n_security_policy, s2n_security_policy_selection,
    s2n_signature_scheme, security_policy_selection,
};

pub fn security_policy_table() -> &'static [s2n_security_policy_selection] {
    unsafe {
        // Get a pointer to the security_policy_selection global array
        let table_pointer =
            &raw const security_policy_selection as *const s2n_security_policy_selection;

        let count = {
            let mut current = table_pointer;
            let mut count = 0;
            while !(*current).version.is_null() {
                count += 1;
                current = current.add(1);
            }
            count
        };

        std::slice::from_raw_parts(table_pointer, count)
    }
}

/// replacement for [`std::ptr::dangling`] which wasn't stabilized until 1.84
fn dangling_ptr<T>() -> *const T {
    let dummy: u64 = 1;
    &dummy as *const u64 as *const T
}

impl s2n_security_policy {
    pub fn ciphers(&self) -> &[&s2n_cipher_suite] {
        let preferences = unsafe { &*self.cipher_preferences };
        let count = preferences.count as usize;
        let ciphers = preferences.suites as *mut &s2n_cipher_suite;
        unsafe { std::slice::from_raw_parts(ciphers, count) }
    }

    pub fn kems(&self) -> &[&s2n_kem_group] {
        let preferences = unsafe { &*self.kem_preferences };
        let count = preferences.tls13_kem_group_count as usize;
        let kems = preferences.tls13_kem_groups as *mut &s2n_kem_group;
        if count == 0 {
            unsafe { std::slice::from_raw_parts(dangling_ptr(), 0) }
        } else {
            unsafe { std::slice::from_raw_parts(kems, count) }
        }
    }

    pub fn curves(&self) -> &[&s2n_ecc_named_curve] {
        let preferences = unsafe { &*self.ecc_preferences };
        let count = preferences.count as usize;
        let curves = preferences.ecc_curves as *mut &s2n_ecc_named_curve;

        if count == 0 {
            unsafe { std::slice::from_raw_parts(dangling_ptr(), 0) }
        } else {
            unsafe { std::slice::from_raw_parts(curves, count) }
        }
    }

    pub fn signatures(&self) -> &[&s2n_signature_scheme] {
        let preferences = unsafe { &*self.signature_preferences };
        let count = preferences.count as usize;
        let curves = preferences.signature_schemes as *mut &s2n_signature_scheme;
        if count == 0 {
            unsafe { std::slice::from_raw_parts(dangling_ptr(), 0) }
        } else {
            unsafe { std::slice::from_raw_parts(curves, count) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn test_security_policy() {
        let policies = security_policy_table();
        assert!(!policies.is_empty());

        let default = policies
            .iter()
            .find(|policy| {
                let name = unsafe { CStr::from_ptr(policy.version) };
                name.to_str().unwrap() == "default"
            })
            .map(|default| unsafe { &*default.security_policy })
            .unwrap();

        assert!(!default.ciphers().is_empty());
        assert!(!default.curves().is_empty());
        assert!(!default.kems().is_empty());
        assert!(!default.signatures().is_empty());
    }
}
