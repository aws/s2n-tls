// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

fn main() {
    // ensure the build script exports the include directory
    let include_dir = std::env::var("DEP_S2N_TLS_INCLUDE").expect("missing DEP_S2N_TLS_INCLUDE");
    let include_dir = PathBuf::from(include_dir);

    // make sure that `s2n.h` is available
    let api = std::fs::read_to_string(include_dir.join("s2n.h")).unwrap();
    assert!(api.contains("s2n_negotiate"));

    // re-export the AWS-LC version to allow us to declare internal symbols in libcrypto.
    // 
    // This is used for access to internal methods like "override_entropy_source_method_FOR_TESTING".
    let version = std::env::vars()
        .find_map(|(key, _)| {
            key.strip_prefix("DEP_AWS_LC_")?
                .strip_suffix("_INCLUDE")
                .map(str::to_owned)
        })
        .expect("missing DEP_AWS_LC_*_INCLUDE; aws-lc-sys must be a direct dependency");
    println!(
        "cargo:rustc-env=AWS_LC_SYMBOL_PREFIX=aws_lc_{}",
        version.to_lowercase()
    );
}
