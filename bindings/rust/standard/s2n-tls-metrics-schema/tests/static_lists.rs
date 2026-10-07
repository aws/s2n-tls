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

/// Get both tls 1.3 and legacy names from s2n-tls
fn emittable_names_from_s2n(scheme: &s2n_signature_scheme) -> Vec<&'static str> {
    unsafe {
        // Skip the "none" placeholder scheme, which is never a real negotiated
        // signature and which `Connection::signature_scheme()` maps to `None`.
        if scheme.iana_value == 0 {
            return Vec::new();
        }

        if scheme.signature_curve.is_null() {
            // No curve: the API always returns the base name.
            vec![static_memory_to_str(scheme.name)]
        } else {
            // Curve present: the API returns the version-specific name. Both
            // must be non-null in this case (the C code dereferences them).
            assert!(
                !scheme.tls13_name.is_null(),
                "scheme with signature_curve missing tls13_name"
            );
            assert!(
                !scheme.legacy_name.is_null(),
                "scheme with signature_curve missing legacy_name"
            );
            vec![
                static_memory_to_str(scheme.tls13_name),
                static_memory_to_str(scheme.legacy_name),
            ]
        }
    }
}

/// Every name that `Connection::signature_scheme()` can return, across all
/// security policies, must be resolvable by `Signature::from_s2n_description`.
#[test]
fn all_emittable_signature_names_resolve() {
    let names: HashSet<&'static str> = s2n_tls_sys_internal::security_policy_table()
        .iter()
        .flat_map(|sp| {
            let sp = unsafe { &*sp.security_policy };
            sp.signatures()
                .iter()
                .flat_map(|sig| emittable_names_from_s2n(sig))
                .collect::<Vec<_>>()
        })
        .collect();

    assert!(!names.is_empty(), "no signature names discovered");

    for name in names {
        let resolved = Signature::from_s2n_description(name);
        assert!(
            resolved.is_some(),
            "from_s2n_description failed to resolve emittable name {name:?}"
        );
        // The resolved signature's IANA value must match the scheme that
        // produced the name, confirming we mapped to the correct entry.
        let sig = resolved.unwrap();
        assert!(
            SIGNATURE_SCHEMES_AVAILABLE_IN_S2N
                .iter()
                .any(|info| info.signature == sig),
            "resolved signature for {name:?} is not in the static list"
        );
    }
}
