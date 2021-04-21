// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    let mut build = cc::Build::new();

    let pq = option_env("CARGO_FEATURE_PQ").is_some();

    // TODO each pq section needs to be built separately since it
    //      has its own relative include paths
    assert!(!pq, "pq builds are not currently supported");

    build.files(include!("./files.rs").iter().copied().filter(|file| {
        // the pq entry file is still needed
        if *file == "lib/pq-crypto/s2n_pq.c" {
            return true;
        }

        if file.starts_with("lib/pq-crypto/") {
            return pq;
        }

        true
    }));

    build
        // pull the include path from the openssl-sys dependency
        .include(env("DEP_OPENSSL_INCLUDE"))
        .include("lib")
        .include("lib/api")
        .flag("-std=c11")
        .flag("-fgnu89-inline")
        // make sure the stack is non-executable
        .flag_if_supported("-z relro")
        .flag_if_supported("-z now")
        .flag_if_supported("-z noexecstack")
        // we use some deprecated libcrypto features so don't warn here
        .flag_if_supported("-Wno-deprecated-declarations")
        .define("_POSIX_C_SOURCE", "200112L");

    // fortify source is only availabe in release mode
    if env("PROFILE") == "release" {
        build.define("_FORTIFY_SOURCE", "2");
    }

    if !pq {
        build.define("S2N_NO_PQ", "1");
    }

    // TODO add features

    // don't spit out a bunch of warnings to the end user
    build.warnings(false);

    build.compile("s2n-tls");

    // tell rust we're linking with libcrypto
    println!("cargo:rustc-link-lib=crypto");
}

fn env<N: AsRef<str>>(name: N) -> String {
    option_env(name).expect("missing env var")
}

fn option_env<N: AsRef<str>>(name: N) -> Option<String> {
    let name = name.as_ref();
    eprintln!("cargo:rerun-if-env-changed={}", name);
    std::env::var(name).ok()
}
