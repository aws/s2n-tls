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
}
