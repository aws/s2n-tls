// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");

    let s2n_tls_sys_dir = PathBuf::from("../../extended/s2n-tls-sys");
    let s2n_lib_include_path = s2n_tls_sys_dir.join("lib");

    let bindings = bindgen::Builder::default()
        // The input header we would like to generate bindings for
        .header("wrapper.h")
        .clang_arg(format!("-I{}", s2n_lib_include_path.display()))
        .clang_arg(format!("-I{}/api", s2n_lib_include_path.display()))
        .size_t_is_usize(true)
        .allowlist_type("s2n_security_policy_selection")
        .allowlist_type("s2n_security_policy")
        .allowlist_type("s2n_cipher_preferences")
        .allowlist_type("s2n_cipher_suite")
        .allowlist_type("s2n_ecc_preferences")
        .allowlist_type("s2n_ecc_named_curve")
        .allowlist_type("s2n_kem_preferences")
        .allowlist_type("s2n_kem_group")
        .allowlist_var("security_policy_selection")
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
