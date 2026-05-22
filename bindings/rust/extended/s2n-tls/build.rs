// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

const EXTERNAL_BUILD_ENV_NAME: &str = "DEP_S2N_TLS_EXTERNAL_BUILD";
const EXTERNAL_BUILD_CFG_NAME: &str = "s2n_tls_external_build";

fn main() {
    println!("cargo:rustc-check-cfg=cfg({EXTERNAL_BUILD_CFG_NAME})");

    /* s2n-tls-sys exports the external build environment variable when libs2n is externally
     * linked. Set a cfg attribute in this case to allow s2n-tls to be aware of the external build.
     */
    if let Ok(external_build_var) = std::env::var(EXTERNAL_BUILD_ENV_NAME) {
        println!("cargo:rerun-if-env-changed={EXTERNAL_BUILD_ENV_NAME}");

        let external_build: bool = external_build_var.parse().unwrap();
        if external_build {
            println!("cargo:rustc-cfg={EXTERNAL_BUILD_CFG_NAME}");
        }
    }
}
