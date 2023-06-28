// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

fn main() {
    let external = External::default();
    if external.is_enabled() {
        external.link();
    } else {
        #[cfg(feature = "cmake")]
        {
            // branch on a runtime value so we don't get unused code warnings
            if option_env("CARGO_FEATURE_CMAKE").is_some() {
                build_cmake();
            } else {
                build_vendored();
            }
        }

        #[cfg(not(feature = "cmake"))]
        build_vendored();
    }
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
    builder: cc::Build,
    out_dir: &'a Path,
}

impl<'a> FeatureDetector<'a> {
    pub fn new(out_dir: &'a Path) -> Self {
        let builder = builder();
        Self { builder, out_dir }
    }

    pub fn supports(&self, name: &str) -> bool {
        let mut build = self.builder.get_compiler().to_command();

        let global_flags = std::path::Path::new("lib/tests/features/GLOBAL.flags");
        assert!(
            global_flags.exists(),
            "missing flags file: {:?}",
            global_flags.display()
        );

        let global_flags = std::fs::read_to_string(global_flags).unwrap();
        for flag in global_flags.trim().split(' ').filter(|f| !f.is_empty()) {
            build.arg(flag);
        }

        let base = std::path::Path::new("lib/tests/features").join(name);

        let file = base.with_extension("c");
        assert!(file.exists(), "missing feature file: {:?}", file.display());

        let probe_flags = base.with_extension("flags");
        assert!(
            probe_flags.exists(),
            "missing flags file: {:?}",
            probe_flags.display()
        );

        let probe_flags = std::fs::read_to_string(probe_flags).unwrap();
        for flag in probe_flags.trim().split(' ').filter(|f| !f.is_empty()) {
            build.arg(flag);
        }

        build
            // just compile the file and don't link
            .arg("-c")
            .arg("-o")
            .arg(self.out_dir.join(name).with_extension("o"))
            .arg(&file);

        eprintln!("=== Testing feature {name} ===");
        build.status().unwrap().success()
    }
}

fn build_vendored() {
    let mut build = builder();

    let pq = option_env("CARGO_FEATURE_PQ").is_some();

    // TODO each pq section needs to be built separately since it
    //      has its own relative include paths
    assert!(!pq, "pq builds are not currently supported without cmake");

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

    if env("PROFILE") == "release" {
        // fortify source is only available in release mode
        build.define("_FORTIFY_SOURCE", "2");
        build.define("NDEBUG", "1");

        // build s2n-tls with LTO if supported
        if build.get_compiler().is_like_gnu() {
            build
                .flag_if_supported("-flto")
                .flag_if_supported("-ffat-lto-objects");
        }
    }

    if !pq {
        build.define("S2N_NO_PQ", "1");
    }

    let out_dir = PathBuf::from(env("OUT_DIR"));

    let features = FeatureDetector::new(&out_dir);

    let mut feature_names = std::fs::read_dir("lib/tests/features")
        .expect("missing features directory")
        .flatten()
        .filter(|file| {
            let file = file.path();
            file.extension().map_or(false, |ext| ext == "c")
        })
        .map(|file| {
            file.path()
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>();

    feature_names.sort();

    for name in &feature_names {
        let is_supported = features.supports(name);
        eprintln!("{name}: {is_supported}");
        if is_supported {
            build.define(name, "1");

            // stacktraces are only available if execinfo is
            if name == "S2N_EXECINFO_AVAILABLE" && option_env("CARGO_FEATURE_STACKTRACE").is_some()
            {
                build.define("S2N_STACKTRACE", "1");
            }
        }
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

fn builder() -> cc::Build {
    let mut build = cc::Build::new();

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

    build
}

#[cfg(feature = "cmake")]
fn build_cmake() {
    let mut config = cmake::Config::new("lib");

    // sometimes openssl-sys decides not to set this value so we may need to set it anyway
    if option_env("DEP_OPENSSL_ROOT").is_none() {
        let include = env("DEP_OPENSSL_INCLUDE");
        if let Some(root) = Path::new(&include).parent() {
            std::env::set_var("DEP_OPENSSL_ROOT", root);
        }
    }

    config
        .register_dep("openssl")
        .configure_arg("-DBUILD_TESTING=off");

    if option_env("CARGO_FEATURE_PQ").is_none() {
        config.configure_arg("-DS2N_NO_PQ=on");
    }

    let dst = config.build();

    let lib = search(dst.join("lib64"))
        .or_else(|| search(dst.join("lib")))
        .or_else(|| search(dst.join("build").join("lib")))
        .expect("could not build libs2n");

    // link the built artifact
    if lib.join("libs2n.a").exists() {
        println!("cargo:rustc-link-lib=static=s2n");
    } else {
        println!("cargo:rustc-link-lib=s2n");
    }

    println!("cargo:include={}", dst.join("include").display());

    // tell rust we're linking with libcrypto
    println!("cargo:rustc-link-lib=crypto");

    fn search(path: PathBuf) -> Option<PathBuf> {
        if path.exists() {
            println!("cargo:rustc-link-search={}", path.display());
            Some(path)
        } else {
            None
        }
    }
}

struct External {
    lib_dir: Option<PathBuf>,
    include_dir: Option<PathBuf>,
}

impl Default for External {
    fn default() -> Self {
        let dir = option_env("S2N_TLS_DIR").map(PathBuf::from);

        let lib_dir = option_env("S2N_TLS_LIB_DIR")
            .map(PathBuf::from)
            .or_else(|| dir.as_ref().map(|d| d.join("lib")));

        let include_dir = option_env("S2N_TLS_INCLUDE_DIR")
            .map(PathBuf::from)
            .or_else(|| dir.as_ref().map(|d| d.join("include")));

        Self {
            lib_dir,
            include_dir,
        }
    }
}

impl External {
    fn is_enabled(&self) -> bool {
        self.lib_dir.is_some()
    }

    fn link(&self) {
        println!(
            "cargo:rustc-link-search={}",
            self.lib_dir.as_ref().unwrap().display()
        );
        println!("cargo:rustc-link-lib=s2n");

        // tell rust we're linking with libcrypto
        println!("cargo:rustc-link-lib=crypto");

        if let Some(include_dir) = self.include_dir.as_ref() {
            println!("cargo:include={}", include_dir.display());
        }
    }
}
