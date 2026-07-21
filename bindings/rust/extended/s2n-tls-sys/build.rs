// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

const EXTERNAL_BUILD_CFG_NAME: &str = "s2n_tls_external_build";

fn main() {
    println!("cargo:rustc-check-cfg=cfg({EXTERNAL_BUILD_CFG_NAME})");

    let external = External::default();
    if external.is_enabled() {
        external.link();
    } else {
        build_vendored();
    }
}

fn env<N: AsRef<str>>(name: N) -> String {
    let name = name.as_ref();
    option_env(name).unwrap_or_else(|| panic!("missing env var {name:?}"))
}

fn option_env<N: AsRef<str>>(name: N) -> Option<String> {
    let name = name.as_ref();
    println!("cargo:rerun-if-env-changed={name}");
    std::env::var(name).ok()
}

struct FeatureDetector<'a> {
    builder: cc::Build,
    out_dir: &'a Path,
}

impl<'a> FeatureDetector<'a> {
    pub fn new(out_dir: &'a Path, libcrypto: &Libcrypto) -> Self {
        let builder = builder(libcrypto);
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
    let libcrypto = Libcrypto::default();

    let mut build = builder(&libcrypto);

    build.files(include!("./files.rs"));

    // https://doc.rust-lang.org/cargo/reference/environment-variables.html
    // * OPT_LEVEL, DEBUG — values of the corresponding variables for the profile currently being built.
    // * PROFILE — release for release builds, debug for other builds. This is determined based on if
    //   the profile inherits from the dev or release profile. Using this environment variable is not
    //   recommended. Using other environment variables like OPT_LEVEL provide a more correct view of
    //   the actual settings being used.
    if env("OPT_LEVEL") != "0" {
        build.define("S2N_BUILD_RELEASE", "1");
        build.define("NDEBUG", "1");

        // Enable cross-file LTO of libs2n, choosing an approach that is safe
        // for the compiler + linker combination in use:
        //
        //  * GCC emits fat-LTO objects (`-ffat-lto-objects`) embedding both
        //    GIMPLE and native code. GNU bfd performs LTO on them; other
        //    linkers (including rust-lld) ignore the LTO and just link the
        //    embedded native code with no LTO, but the link succeeds. Safe with
        //    any linker.
        //
        //  * Clang emits LLVM bitcode (`-flto`). rust-lld consumes it, but a
        //    plain GNU `ld` cannot and the link FAILS with "File format not
        //    recognized" (this is why #3968 restricted LTO to GCC). So we only
        //    enable Clang LTO when we know the linker is rust-lld.
        //
        // Since Rust 1.90, rust-lld is the default linker on
        // x86_64-unknown-linux-gnu. rust-lld can't consume GCC's fat-LTO
        // objects, so on that target we prefer Clang to keep LTO working; if
        // only GCC is available there, LTO is silently dropped and we warn.
        if rust_lld_is_default() {
            if build.get_compiler().is_like_clang() || try_prefer_clang(&mut build) {
                build.flag_if_supported("-flto");
            } else if build.get_compiler().is_like_gnu() {
                build
                    .flag_if_supported("-flto")
                    .flag_if_supported("-ffat-lto-objects");

                // GCC + rust-lld: the fat-LTO objects are ignored by rust-lld,
                // so the LTO pass is silently dropped (~2-4% per TLS handshake).
                println!(
                    "cargo:warning=s2n-tls-sys: cross-file LTO of the vendored libs2n is \
                     silently disabled. Clang was not found, so the C code was built with \
                     GCC fat-LTO objects, which the default rust-lld linker (Rust >= 1.90 on \
                     x86_64-unknown-linux-gnu) cannot consume, costing ~2-4% per TLS handshake. \
                     Install clang (preferred, restores LTO automatically) or build with \
                     RUSTFLAGS=\"-Clinker-features=-lld\" to fall back to the GNU bfd linker. \
                     For details see: \
                     https://github.com/aws/s2n-tls/blob/main/bindings/rust/extended/s2n-tls-sys/README.md#performance-note-rust--190-lto-and-the-linker"
                );
            }
        } else if build.get_compiler().is_like_gnu() {
            // Non-rust-lld linker (e.g. GNU bfd, macOS ld). GCC fat-LTO objects
            // link everywhere. We deliberately do NOT add `-flto` for Clang
            // here: its bitcode would fail to link with a plain GNU `ld`
            // (see #3968), and pre-1.90 this target used bfd by default.
            build
                .flag_if_supported("-flto")
                .flag_if_supported("-ffat-lto-objects");
        }
    }

    let out_dir = PathBuf::from(env("OUT_DIR"));

    let features = FeatureDetector::new(&out_dir, &libcrypto);

    let mut feature_names = std::fs::read_dir("lib/tests/features")
        .expect("missing features directory")
        .flatten()
        .filter(|file| {
            let file = file.path();
            file.extension().is_some_and(|ext| ext == "c")
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

    // linking to the libcrypto is handled by the rust compiler through the
    // `extern crate aws_lc_rs as _;` statement included in the generated source
    // files. This is less brittle than manually linking the libcrypto artifact.

    // let consumers know where to find our header files
    let include_dir = out_dir.join("include");
    std::fs::create_dir_all(&include_dir).unwrap();
    std::fs::copy("lib/api/s2n.h", include_dir.join("s2n.h")).unwrap();
    println!("cargo:include={}", include_dir.display());
}

/// Try to switch `build` to use Clang so that cross-file LTO works under
/// rust-lld (the default linker on x86_64-unknown-linux-gnu since Rust 1.90).
///
/// Returns true if Clang was selected. This is a no-op (returns false) when:
///   * the user explicitly set `CC` or
///   * `clang` isn't on PATH / isn't runnable.
fn try_prefer_clang(build: &mut cc::Build) -> bool {
    let target = std::env::var("TARGET").unwrap_or_default();
    if std::env::var("CC").is_ok()
        || std::env::var(format!("CC_{target}")).is_ok()
        || std::env::var(format!("CC_{}", target.replace('-', "_"))).is_ok()
    {
        return false;
    }

    let clang_runs = std::process::Command::new("clang")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);
    if !clang_runs {
        return false;
    }

    build.compiler("clang");
    true
}

/// Returns true if the final linker for this build is (most likely) rust-lld.
///
/// This gates the LTO strategy: rust-lld can consume Clang's LLVM bitcode but
/// not GCC's fat-LTO objects, whereas a plain GNU `ld` is the opposite (it
/// fails on Clang bitcode, see #3968). rust-lld became the default linker on
/// x86_64-unknown-linux-gnu in Rust 1.90.
///
/// Every check fails open: if we can't positively confirm rust-lld is in use,
/// we return false and take the GCC-fat-LTO path that links with any linker.
fn rust_lld_is_default() -> bool {
    // Only x86_64-unknown-linux-gnu defaults to rust-lld.
    if std::env::var("TARGET").as_deref() != Ok("x86_64-unknown-linux-gnu") {
        return false;
    }

    // If the user already opted out of rust-lld, the GNU bfd linker will
    // consume the fat-LTO objects, so there's nothing to warn about.
    // CARGO_ENCODED_RUSTFLAGS captures both RUSTFLAGS and build.rustflags /
    // target.<triple>.rustflags from .cargo/config.toml.
    if let Ok(flags) = std::env::var("CARGO_ENCODED_RUSTFLAGS") {
        if flags.contains("linker-features=-lld") {
            return false;
        }
    }

    // rust-lld only became the default on this target in Rust 1.90.
    // Fail open: if the version can't be determined, stay silent.
    match rustc_version::version() {
        Ok(version) => version >= rustc_version::Version::new(1, 90, 0),
        Err(_) => false,
    }
}

fn builder(libcrypto: &Libcrypto) -> cc::Build {
    let mut build = cc::Build::new();

    let includes = [&libcrypto.include, "lib", "lib/api"];
    if let Ok(cflags) = std::env::var("CFLAGS") {
        // cc will read the CFLAGS env variable and prepend the compiler
        // command with all flags and includes from it, which may conflict
        // with the includes we specify. To ensure that our includes show
        // up first in the compiler command, we prepend them to CFLAGS.
        std::env::set_var("CFLAGS", format!("-I {} {}", includes.join(" -I "), cflags));
    } else {
        build.includes(includes);
    };

    build
        .flag("-include")
        .flag("lib/utils/s2n_prelude.h")
        .flag("-std=c11")
        .flag("-fgnu89-inline")
        // make sure the stack is non-executable
        .flag_if_supported("-z relro")
        .flag_if_supported("-z now")
        .flag_if_supported("-z noexecstack")
        // we use some deprecated libcrypto features so don't warn here
        .flag_if_supported("-Wno-deprecated-declarations")
        .flag_if_supported("-Wa,-mbranches-within-32B-boundaries");

    build
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Libcrypto {
    version: String,
    link: String,
    include: String,
    root: String,
}

impl Default for Libcrypto {
    fn default() -> Self {
        for (name, value) in std::env::vars() {
            if let Some(version) = name.strip_prefix("DEP_AWS_LC_") {
                if let Some(version) = version.strip_suffix("_INCLUDE") {
                    let version = version.to_string();

                    println!("cargo:rerun-if-env-changed={name}");

                    let include = value;
                    let root = env(format!("DEP_AWS_LC_{version}_ROOT"));
                    let link = env(format!("DEP_AWS_LC_{version}_LIBCRYPTO"));

                    return Self {
                        version,
                        link,
                        include,
                        root,
                    };
                }
            }
        }

        panic!("missing DEP_AWS_LC paths");
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
        println!("cargo:rustc-cfg={EXTERNAL_BUILD_CFG_NAME}");

        // Propagate an external build flag to dependents, of the form
        // `DEP_S2N_TLS_EXTERNAL_BUILD=true`.
        println!("cargo:external_build=true");

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
