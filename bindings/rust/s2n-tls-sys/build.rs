// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

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

    // fortify source is only available in release mode
    if env("PROFILE") == "release" {
        build.define("_FORTIFY_SOURCE", "2");
    }

    if !pq {
        build.define("S2N_NO_PQ", "1");
    }

    let out_dir = PathBuf::from(env("OUT_DIR"));

    let features = FeatureDetector::new(&out_dir);

    if features.supports("execinfo") {
        build.define("S2N_HAVE_EXECINFO", "1");
    }

    if features.supports("cpuid") {
        build.define("S2N_CPUID_AVAILABLE", "1");
    }

    if features.supports("fallthrough") {
        build.define("FALL_THROUGH_SUPPORTED", "1");
    }

    if features.supports("__restrict__") {
        build.define("__RESTRICT__SUPPORTED", "1");
    }

    // don't spit out a bunch of warnings to the end user, since they won't really be able
    // to do anything with it
    build.warnings(false);

    build.compile("s2n-tls");

    // tell rust we're linking with libcrypto
    println!("cargo:rustc-link-lib=crypto");

    // let consumers know where to find our header files
    let include_dir = out_dir.join("include");
    std::fs::create_dir_all(&include_dir).unwrap();
    std::fs::copy("lib/api/s2n.h", include_dir.join("s2n.h")).unwrap();
    println!("cargo:include={}", include_dir.display());
}

fn env<N: AsRef<str>>(name: N) -> String {
    option_env(name).expect("missing env var")
}

fn option_env<N: AsRef<str>>(name: N) -> Option<String> {
    let name = name.as_ref();
    eprintln!("cargo:rerun-if-env-changed={}", name);
    std::env::var(name).ok()
}

struct FeatureDetector<'a> {
    out_dir: &'a std::path::Path,
}

impl<'a> FeatureDetector<'a> {
    pub fn new(out_dir: &'a Path) -> Self {
        Self { out_dir }
    }

    pub fn supports(&self, name: &str) -> bool {
        let out = self.out_dir.join("features").join(name);
        let out = out.to_str().unwrap();

        cc::Build::new()
            .file(
                std::path::Path::new("lib/tests/features")
                    .join(name)
                    .with_extension("c"),
            )
            // don't print anything
            .cargo_metadata(false)
            // make sure it doesn't warn
            .warnings(true)
            .debug(false)
            // set the archiver to the `true` program, since we don't actually link anything
            .archiver("true")
            .try_compile(out)
            .is_ok()
    }
}
