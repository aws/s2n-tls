// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls_metrics_schema::static_lists::*;
use s2n_tls_sys_internal::{
    s2n_cipher_suite, s2n_ecc_named_curve, s2n_kem_group, s2n_signature_scheme,
};
use std::{
    collections::HashSet,
    ffi::{CStr, c_char},
};

unsafe fn static_memory_to_str(value: *const c_char) -> &'static str {
    unsafe { CStr::from_ptr(value).to_str().unwrap() }
}

fn cipher_info_from_s2n(s2n_cipher: &s2n_cipher_suite) -> CipherInformation {
    unsafe {
        let openssl_name = static_memory_to_str(s2n_cipher.name);
        let iana_description = static_memory_to_str(s2n_cipher.iana_name);
        let iana_value = s2n_cipher.iana_value;
        CipherInformation::new(iana_description, iana_value, openssl_name)
    }
}

fn group_info_from_s2n_kem(kem_group: &s2n_kem_group) -> GroupInformation {
    unsafe {
        let name = static_memory_to_str(kem_group.name);
        let iana_id = kem_group.iana_id;
        GroupInformation::new(name, iana_id)
    }
}

fn group_info_from_s2n_ecc(curve: &s2n_ecc_named_curve) -> GroupInformation {
    unsafe {
        let name = static_memory_to_str(curve.name);
        let iana_id = curve.iana_id;
        GroupInformation::new(name, iana_id)
    }
}

fn sig_info_from_s2n(scheme: &s2n_signature_scheme) -> SignatureSchemeInformation {
    unsafe {
        let name = static_memory_to_str(scheme.name);
        let iana_value = scheme.iana_value;
        SignatureSchemeInformation::new(name, iana_value)
    }
}

fn all_available_ciphers() -> Vec<CipherInformation> {
    let ciphers: HashSet<CipherInformation> = s2n_tls_sys_internal::security_policy_table()
        .iter()
        .flat_map(|sp| {
            let sp = unsafe { &*sp.security_policy };
            sp.ciphers()
                .iter()
                .cloned()
                .map(cipher_info_from_s2n)
                .collect::<Vec<_>>()
        })
        .collect();
    let mut ciphers: Vec<CipherInformation> = ciphers.into_iter().collect();
    ciphers.sort_by_key(|cipher| cipher.iana_description);
    ciphers
}

fn all_available_groups() -> Vec<GroupInformation> {
    let groups: HashSet<GroupInformation> = s2n_tls_sys_internal::security_policy_table()
        .iter()
        .flat_map(|sp| {
            let sp = unsafe { &*sp.security_policy };
            let curves = sp
                .curves()
                .iter()
                .map(|curve| group_info_from_s2n_ecc(curve));
            let kem_groups = sp.kems().iter().map(|kem| group_info_from_s2n_kem(kem));
            curves.chain(kem_groups).collect::<Vec<GroupInformation>>()
        })
        .collect();
    let mut groups: Vec<GroupInformation> = groups.into_iter().collect();
    groups.sort_by_key(|group| group.iana_description);
    groups
}

fn all_available_signatures() -> Vec<SignatureSchemeInformation> {
    let sigs: HashSet<SignatureSchemeInformation> = s2n_tls_sys_internal::security_policy_table()
        .iter()
        .flat_map(|sp| {
            let sp = unsafe { &*sp.security_policy };
            sp.signatures().iter().map(|sig| sig_info_from_s2n(sig))
        })
        .collect();
    let mut sigs: Vec<SignatureSchemeInformation> = sigs.into_iter().collect();
    sigs.sort_by_key(|sig| sig.description);
    sigs
}

#[test]
fn all_ciphers_in_static_list() {
    let ciphers = all_available_ciphers();
    assert_eq!(ciphers.as_slice(), &CIPHERS_AVAILABLE_IN_S2N[..]);
}

#[test]
fn all_groups_in_static_list() {
    let groups = all_available_groups();
    assert_eq!(groups.as_slice(), &GROUPS_AVAILABLE_IN_S2N[..]);
}

#[test]
fn all_signature_schemes_in_static_list() {
    let schemes = all_available_signatures();
    assert_eq!(schemes.as_slice(), &SIGNATURE_SCHEMES_AVAILABLE_IN_S2N[..]);
}
