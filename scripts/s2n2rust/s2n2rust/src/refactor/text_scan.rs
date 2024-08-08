use super::*;
use core::ops::ControlFlow;
use glob::glob;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::sync::Arc;

pub fn run(sh: &Shell, c_src: &Path, rust_src: &Path, overrides: &Overrides) -> Result {
    let structs = index_structs(sh, c_src, overrides)?;
    let config = Arc::new(Config { structs });

    std::env::set_current_dir(rust_src)?;
    for file in glob("src/**/*.rs")?.flatten() {
        if overrides.contains(&file) || file == Path::new("src/error/s2n_errno_errors.rs") {
            continue;
        }
        let _ = process_file(&file, &config);
    }
    Ok(())
}

type StructIndex = HashMap<String, Owner>;

#[derive(Clone, Debug)]
struct Owner {
    path: String,
    module: String,
}

fn index_structs(_sh: &Shell, c_src: &Path, _overrides: &Overrides) -> Result<StructIndex> {
    std::env::set_current_dir(c_src)?;

    let mut modules = HashMap::new();

    modules.insert(
        "s2n_result".to_string(),
        Owner {
            path: "utils/s2n_result".into(),
            module: "utils::s2n_result".into(),
        },
    );

    modules.insert(
        "s2n_blinding_guard".to_string(),
        Owner {
            path: "utils/s2n_safety".into(),
            module: "utils::s2n_safety".into(),
        },
    );

    modules.insert(
        "s2n_debug_info".to_string(),
        Owner {
            path: "error/s2n_errno".into(),
            module: "error::s2n_errno".into(),
        },
    );

    // async pkey structs are private
    for s in ["decrypt_data", "sign_data", "op", "op_actions"] {
        modules.insert(
            format!("s2n_async_pkey_{s}"),
            Owner {
                path: "tls/s2n_async_pkey".into(),
                module: "tls::s2n_async_pkey".into(),
            },
        );
    }

    // private structs
    for (name, root, module) in [
        ("s2n_hkdf_impl", "crypto", "s2n_hkdf"),
        (
            "s2n_connection_deserialize",
            "tls",
            "s2n_connection_serialize",
        ),
        ("s2n_handshake_action", "tls", "s2n_handshake_io"),
        ("FGN_STATE", "utils", "s2n_fork_detection"),
    ] {
        modules.insert(
            name.into(),
            Owner {
                path: format!("{root}/{module}"),
                module: format!("{root}::{module}"),
            },
        );
    }

    // TODO parse typedef declarations
    {
        modules.insert(
            "s2n_parsed_extension".into(),
            Owner {
                path: "tls/extensions/s2n_extension_list".into(),
                module: "tls::extensions::s2n_extension_list".into(),
            },
        );
        modules.insert(
            "s2n_parsed_extensions_list".into(),
            Owner {
                path: "tls/extensions/s2n_extension_list".into(),
                module: "tls::extensions::s2n_extension_list".into(),
            },
        );
        modules.insert(
            "s2n_extension_type".into(),
            Owner {
                path: "tls/extensions/s2n_extension_type".into(),
                module: "tls::extensions::s2n_extension_type".into(),
            },
        );
        modules.insert(
            "s2n_extension_type_list".into(),
            Owner {
                path: "tls/extensions/s2n_extension_type_lists".into(),
                module: "tls::extensions::s2n_extension_type_lists".into(),
            },
        );
        modules.insert(
            "s2n_atomic_flag".into(),
            Owner {
                path: "utils/s2n_atomic".into(),
                module: "utils::s2n_atomic".into(),
            },
        );
    }

    for root in ["api", "crypto", "stuffer", "tls", "utils"] {
        for file in glob(&format!("{root}/**/*.h"))?.flatten() {
            let file_name = file
                .file_stem()
                .map(|v| v.to_string_lossy().to_string())
                .unwrap_or_default();

            let (root, file_name) = match file_name.as_str() {
                "s2n_map_internal" => ("utils", "s2n_map"),
                "s2n_kex_data" => ("tls", "s2n_kex"),
                "s2n_cipher" => ("crypto", "s2n_aead_cipher_aes_gcm"),
                "s2n_ktls_crypto" => ("tls", "s2n_ktls"),
                "s2n_ktls_parameters" => ("tls", "s2n_ktls"),
                "s2n_evp" => ("tls", "s2n_prf"),
                file => (root, file),
            };

            let owner = Owner {
                path: format!("{root}/{file_name}"),
                module: format!("{root}::{file_name}"),
            };

            let mut scan = || {
                let file = File::open(&file)?;
                let file = BufReader::new(file);
                for line in file.lines() {
                    let line = line?;

                    let Some(name) = line
                        .strip_prefix("struct ")
                        .or_else(|| line.strip_prefix("union "))
                    else {
                        continue;
                    };

                    let Some(name) = name.strip_suffix(" {") else {
                        continue;
                    };

                    if !modules.contains_key(name) {
                        modules.insert(name.to_string(), owner.clone());
                    }
                }

                <Result>::Ok(())
            };

            let _ = scan();
        }
    }
    Ok(modules)
}

#[derive(Debug)]
struct Config {
    structs: StructIndex,
}

fn process_file(path: &Path, config: &Arc<Config>) -> Result {
    eprintln!(
        "Processing {}",
        path.strip_prefix("src/").unwrap().display()
    );

    let original = path.with_extension("bkup");
    if !original.exists() {
        std::fs::copy(path, &original)?;
    }

    let file = File::open(&original)?;
    let file = BufReader::new(file);
    let out = File::create(path)?;
    let mut out = BufWriter::new(out);

    process_text(path, config, file, &mut out)?;

    out.flush()?;
    Ok(())
}

fn process_text(
    path: &Path,
    config: &Arc<Config>,
    file: impl BufRead,
    out: &mut impl Write,
) -> Result {
    let mut processors = Processors::new(path, config);
    for line in file.lines() {
        let mut line = line?;

        // if the line is empty then just skip processing it
        if line.is_empty() {
            writeln!(out)?;
            continue;
        }

        if processors.on_line(&mut line).is_break() {
            continue;
        };

        writeln!(out, "{line}")?;
    }
    Ok(())
}

macro_rules! processors {
    (struct Processors {
        $(
            $lower:ident: $Upper:ty,
        )*
    }) => {
        struct Processors {
            $(
                $lower: $Upper,
            )*
        }

        impl Processors {
            fn new(path: &Path, config: &Arc<Config>) -> Self {
                Self {
                    $(
                        $lower: <$Upper>::new(path, config),
                    )*
                }
            }

            fn on_line(&mut self, line: &mut String) -> ControlFlow<()> {
                $(
                    self.$lower.on_line(line)?;
                )*
                ControlFlow::Continue(())
            }
        }
    }
}

processors!(
    struct Processors {
        const_filter: ConstFilter,
        type_filter: TypeFilter,
        extern_types: ExternTypes,
        no_mangle: NoMangle,
        ensure_ref: EnsureRefMacro,
        ensure: EnsureMacro,
        ensure_dbg: EnsureDbgMacro,
        guard: GuardMacro,
        ok: OkMacro,
        success: SuccessMacro,
        err: ErrMacro,
        err_if: ErrIfMacro,
        err_match: ErrMatchMacro,
        likely: Likely,
        logic: Logic,
        postcondition: PostconditionMacro,
        precondition: PreconditionMacro,
        guard_ossl: GuardOsslMacro,
        ignore_result: IgnoreResult,
        constant_lit: ConstantLiterals,
        stddef: Stddef,
        as_bool: AsBool,
        memmove: MemmoveFn,
        owning_struct: OwningStruct,
        preserve_err: PreserveErrMacro,
        errno_api: ErrnoApi,
        safety_api: SafetyApi,
        unnamed_digest: UnnamedDigest,
        libc: LibcOverride,
        librs: LibRs,
        prelude: Prelude,
        extern_block: ExternBlock,
        libcrypto: LibcryptoPath,
        literal_casts: LiteralCasts,
        encryption_limit: CiphersuiteEncryptionLimit,
        remove_casts: RemoveCasts,
    }
);

/// Removes any redundant imported constants
struct ConstFilter {}

impl ConstFilter {
    fn new(_path: &Path, _config: &Arc<Config>) -> Self {
        Self {}
    }

    fn on_line(&mut self, line: &mut String) -> ControlFlow<()> {
        let trimmed = line.trim_start();
        let Some(candidate) = trimmed.strip_prefix("pub const ") else {
            return ControlFlow::Continue(());
        };
        for prefix in [
            "S2N_ERR_",
            "_SC_",
            "S2N_SUCCESS",
            "S2N_FAILURE",
            "S2N_SSLv2",
            "S2N_SSLv3",
            "S2N_TLS10",
            "S2N_TLS11",
            "S2N_TLS12",
            "S2N_TLS13",
        ] {
            if candidate.starts_with(prefix) {
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    }
}

/// Removes any redundant imported types
struct TypeFilter {}

impl TypeFilter {
    fn new(_path: &Path, _config: &Arc<Config>) -> Self {
        Self {}
    }

    fn on_line(&mut self, line: &mut String) -> ControlFlow<()> {
        let trimmed = line.trim_start();
        let Some(candidate) = trimmed.strip_prefix("pub type ") else {
            return ControlFlow::Continue(());
        };
        for prefix in [
            "__int8_t",
            "__uint8_t",
            "__int16_t",
            "__uint16_t",
            "__int32_t",
            "__uint32_t",
            "__int64_t",
            "__uint64_t",
            "__ssize_t",
            "__size_t",
            "int8_t",
            "uint8_t",
            "int16_t",
            "uint16_t",
            "int32_t",
            "uint32_t",
            "int64_t",
            "uint64_t",
            "ssize_t",
            "size_t",
        ] {
            if candidate.starts_with(prefix) {
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    }
}

/// Removes any extern types
struct ExternTypes {
    config: Arc<Config>,
}

impl ExternTypes {
    fn new(_path: &Path, config: &Arc<Config>) -> Self {
        Self {
            config: config.clone(),
        }
    }

    fn on_line(&mut self, line: &mut String) -> ControlFlow<()> {
        let trimmed = line.trim();
        let Some(ty) = trimmed.strip_prefix("pub type ") else {
            return ControlFlow::Continue(());
        };

        if ty.contains("=") {
            return ControlFlow::Continue(());
        }

        let ty = ty.trim_end_matches(';');

        if let Some(owner) = self.config.structs.get(ty) {
            *line = format!("use crate::{}::{ty};", owner.module);
            return ControlFlow::Continue(());
        }

        match ty {
            ty if ty.starts_with("s2n_") => {
                *line = format!(
                    "compile_error!({:?});",
                    format_args!("UNHANDLED EXTERN TYPE {ty}")
                );
            }
            _ => {
                *line = format!("use crate::libcrypto::{ty};");
            }
        }

        ControlFlow::Continue(())
    }
}

struct ExternBlock {
    enabled: bool,
}

impl ExternBlock {
    fn new(_path: &Path, _config: &Arc<Config>) -> Self {
        Self { enabled: false }
    }

    fn on_line(&mut self, line: &mut String) -> ControlFlow<()> {
        match self.enabled {
            true if line == "}" => {
                self.enabled = false;
                ControlFlow::Break(())
            }
            true if line.starts_with("use ") => ControlFlow::Continue(()),
            true => ControlFlow::Break(()),
            false if line == "extern \"C\" {" => {
                self.enabled = true;
                ControlFlow::Break(())
            }
            false => ControlFlow::Continue(()),
        }
    }
}

struct OwningStruct {
    file_name: String,
    pending_use: Option<String>,
    config: Arc<Config>,
}

impl OwningStruct {
    fn new(path: &Path, config: &Arc<Config>) -> Self {
        let path = path.to_str().unwrap();
        let (_, path) = path.split_once("src/").unwrap();
        let path = path.trim_end_matches(".rs");
        let file_name = path.to_string();
        Self {
            pending_use: None,
            config: config.clone(),
            file_name,
        }
    }

    fn on_line(&mut self, line: &mut String) -> ControlFlow<()> {
        if self.pending_use.is_some() && line != "}" {
            return ControlFlow::Break(());
        }

        if let Some(u) = self.pending_use.take() {
            line.push_str(&u);
            return ControlFlow::Continue(());
        }

        let Some(name) = line
            .strip_prefix("pub struct ")
            .or_else(|| line.strip_prefix("pub union "))
        else {
            return ControlFlow::Continue(());
        };

        let name = name.trim_end_matches(" {").trim_end_matches("<'a>");

        if name.starts_with("C2RustUnnamed") {
            return ControlFlow::Continue(());
        }

        let owner = self.config.structs.get(name);

        let owns_struct = owner.as_ref().map_or(false, |v| &v.path == &self.file_name);

        // if the file doesn't "own" the struct then remove it
        if name == "s2n_result" || !owns_struct {
            self.pending_use = Some(match (name, owner) {
                (name, Some(owner)) => format!("\nuse crate::{}::{name};\n", owner.module),
                (
                    "iovec" | "msghdr" | "cmsghdr" | "timespec" | "stat" | "sockaddr"
                    | "sockaddr_storage",
                    None,
                ) => {
                    format!("\nuse libc::{name};\n")
                }
                // TODO figure out where to pull these from
                (name @ ("__pthread_rwlock_arch_t" | "FGN_STATE"), None) => {
                    println!("UNKNOWN IMPORT {name:?}");
                    "".to_string()
                }
                (name, None) if name.starts_with("s2n_") => {
                    println!("NO OWNER {name:?}");
                    "".to_string()
                }
                _ => format!("\nuse crate::libcrypto::{name};\n"),
            });
            *line = format!("struct __CLEANUP__{name} {{");
        }

        ControlFlow::Continue(())
    }
}

macro_rules! rewrite {
    ($name:ident, [$($pat:expr),* $(,)?], $out:expr $(,)?) => {
        struct $name {}

        impl $name {
            fn new(_path: &Path, _config: &Arc<Config>) -> Self {
                Self {}
            }

            fn on_line(&mut self, line: &mut String) -> ControlFlow<()> {
                let trimmed = line.trim_start();
                for prefix in [
                    $(
                        $pat,
                    )*
                ] {
                    if let Some(remaining) = trimmed.strip_prefix(prefix) {
                        let offset = line.len() - remaining.len();
                        line.replace_range(..offset, $out);
                        return ControlFlow::Continue(());
                    }
                }
                ControlFlow::Continue(())
            }
        }
    };
}

macro_rules! replace {
    ($name:ident, [$($pat:expr),* $(,)?]) => {
        struct $name {}

        impl $name {
            fn new(_path: &Path, _config: &Arc<Config>) -> Self {
                Self {}
            }

            fn on_line(&mut self, line: &mut String) -> ControlFlow<()> {
                for (pat, value) in [
                    $(
                        $pat,
                    )*
                ] {
                    if line.contains(pat) {
                        *line = line.replace(pat, value);
                    }
                }
                ControlFlow::Continue(())
            }
        }
    };
}

// Rewrites any ENSURE_REF calls to the rust macro
rewrite!(
    EnsureRefMacro,
    [
        "__STUB_RESULT_ENSURE_REF(",
        "__STUB_RESULT_ENSURE_MUT(",
        "__STUB_POSIX_ENSURE_REF(",
        "__STUB_POSIX_ENSURE_MUT(",
        "__STUB_PTR_ENSURE_REF(",
        "__STUB_PTR_ENSURE_MUT(",
    ],
    "ensure_ref!("
);

// Rewrites any ENSURE calls to the rust macro
rewrite!(
    EnsureMacro,
    [
        "__STUB_POSIX_ENSURE(",
        "__STUB_RESULT_ENSURE(",
        "__STUB_PTR_ENSURE("
    ],
    "ensure!("
);

// Rewrites any ENSURE calls to the rust macro
rewrite!(
    EnsureDbgMacro,
    [
        "__STUB_POSIX_ENSURE_DEBUG(",
        "__STUB_RESULT_ENSURE_DEBUG(",
        "__STUB_PTR_ENSURE_DEBUG("
    ],
    "ensure_dbg!("
);

// Rewrites any GUARD_OSSL calls to the rust macro
rewrite!(
    GuardOsslMacro,
    [
        "__STUB_POSIX_GUARD_OSSL(",
        "__STUB_RESULT_GUARD_OSSL(",
        "__STUB_PTR_GUARD_OSSL("
    ],
    "guard_ossl!("
);

// Rewrites any GUARD calls to the rust macro
rewrite!(
    GuardMacro,
    [
        "__STUB_RESULT_GUARD(",
        "__STUB_RESULT_GUARD_POSIX(",
        "__STUB_RESULT_GUARD_PTR(",
        "__STUB_POSIX_GUARD(",
        "__STUB_POSIX_GUARD_RESULT(",
        "__STUB_POSIX_GUARD_PTR(",
        "__STUB_PTR_GUARD(",
        "__STUB_PTR_GUARD_RESULT(",
        "__STUB_PTR_GUARD_POSIX(",
    ],
    "guard!("
);

rewrite!(
    LibcOverride,
    ["use ::libc;",],
    r#"
// TODO try to consolidate this list
use crate::libc::{self, __errno_location, nanosleep, strlen, strncasecmp, strchr, clock_gettime, strncmp, close, open, mmap, fstat, write, read, getpeername, setsockopt, getsockopt, pthread_setspecific, pthread_once, pthread_key_create, malloc, mlock, madvise, posix_memalign, free, munlock, getenv, sysconf, pthread_self, atexit, strcasecmp, sendfile, sendmsg, recvmsg, snprintf, memcmp, memset, tolower};
    "#
);

// TODO get the correct version instead
replace!(
    LibcryptoPath,
    [
        ("aws_lc_0_17_0_", "crate::libcrypto::"),
        ("extern \"C\" fn crate::libcrypto::", "extern \"C\" fn ")
    ]
);

replace!(
    ErrnoApi,
    [
        (
            "__STUB_ERROR_IS_BLOCKING(",
            "crate::error::s2n_errno::is_blocking("
        ),
        (
            "__STUB_DEBUG_INFO_GET(",
            "crate::error::s2n_errno::s2n_debug_info::get("
        ),
        (
            "__STUB_DEBUG_INFO_SET(",
            "crate::error::s2n_errno::s2n_debug_info::set("
        ),
        ("__STUB_ERRNO_GET(", "crate::error::s2n_errno::get("),
        ("__STUB_ERRNO_SET(", "crate::error::s2n_errno::set(")
    ]
);

replace!(
    SafetyApi,
    [
        (
            "__STUB_ZERO_TO_DISABLE_DEFER_CLEANUP(",
            "crate::utils::s2n_safety::disable_defer_cleanup("
        ),
        (
            "__STUB_ADD_IS_OVERFLOW_SAFE(",
            "crate::utils::s2n_safety::is_overflow_safe(",
        ),
        (
            "__STUB_WITH_ERROR_BLINDING(",
            "crate::utils::s2n_safety::with_error_blinding(",
        ),
        (
            "__STUB_BLINDING_CANCEL(",
            "crate::utils::s2n_safety::blinding_cancel(",
        ),
    ]
);

/// Removes #[no_mangle] attributes
struct NoMangle {}

impl NoMangle {
    fn new(_path: &Path, _config: &Arc<Config>) -> Self {
        Self {}
    }

    fn on_line(&mut self, line: &mut String) -> ControlFlow<()> {
        if line.contains("#[no_mangle]") {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }
}

// Replaces Ok results with ok macro
rewrite!(
    OkMacro,
    [
        "return __STUB_RESULT_OK();",
        "return 0 as libc::c_int;",
        "return S2N_SUCCESS as libc::c_int;",
        "result S2N_SUCCESS;",
    ],
    "return ok!();"
);

replace!(
    SuccessMacro,
    [
        ("== S2N_SUCCESS as libc::c_int", ".is_ok()"),
        (">= S2N_SUCCESS as libc::c_int", ".is_ok()"),
        ("> S2N_FAILURE as libc::c_int", ".is_ok()"),
        ("!= S2N_SUCCESS as libc::c_int", ".is_error()"),
        ("< S2N_SUCCESS as libc::c_int", ".is_error()"),
        ("__STUB_RESULT_IS_OK(", "Outcome::is_ok("),
        ("__STUB_RESULT_IS_ERROR(", "Outcome::is_error("),
        ("__STUB_RESULT_OK()", "<s2n_result as Outcome>::ok()"),
    ]
);

rewrite!(
    ErrMacro,
    [
        "return __STUB_RESULT_BAIL(",
        "return __STUB_POSIX_BAIL(",
        "return __STUB_PTR_BAIL(",
    ],
    "return error!("
);

replace!(
    ErrMatchMacro,
    [
        ("return __STUB_RESULT_BAIL(", "return error!("),
        ("return __STUB_POSIX_BAIL(", "return error!("),
        ("return __STUB_PTR_BAIL(", "return error!("),
    ]
);

rewrite!(
    ErrIfMacro,
    [
        "__STUB_RESULT_ERROR_IF(",
        "__STUB_POSIX_ERROR_IF(",
        "__STUB_PTR_ERROR_IF(",
    ],
    "error_if!("
);

rewrite!(
    PreconditionMacro,
    [
        "__STUB_RESULT_PRECONDITION(",
        "__STUB_POSIX_PRECONDITION(",
        "__STUB_PTR_PRECONDITION(",
    ],
    "precondition!("
);

rewrite!(
    PostconditionMacro,
    [
        "__STUB_RESULT_POSTCONDITION(",
        "__STUB_POSIX_POSTCONDITION(",
        "__STUB_PTR_POSTCONDITION(",
    ],
    "postcondition!("
);

rewrite!(
    PreserveErrMacro,
    ["__STUB_ERROR_PRESERVE_ERRNO()",],
    "return error!()"
);

rewrite!(
    MemmoveFn,
    [
        "__STUB_RESULT_MEMMOVE(",
        "__STUB_POSIX_MEMMOVE(",
        "__STUB_PTR_MEMMOVE(",
    ],
    "crate::utils::s2n_safety::memmove("
);

replace!(
    UnnamedDigest,
    [
        (
            "digest: C2RustUnnamed_0 {",
            "digest: crate::crypto::s2n_hash::C2RustUnnamed_1 {"
        ),
        (
            "digest: C2RustUnnamed_1 {",
            "digest: crate::crypto::s2n_hash::C2RustUnnamed_1 {"
        ),
        (
            "digest: C2RustUnnamed_2 {",
            "digest: crate::crypto::s2n_hash::C2RustUnnamed_1 {"
        ),
        (
            "digest: C2RustUnnamed_8 {",
            "digest: crate::crypto::s2n_hash::C2RustUnnamed_1 {"
        ),
        (
            "low_level: s2n_hash_low_level_digest {",
            "low_level: crate::crypto::s2n_hash::s2n_hash_low_level_digest {"
        ),
        (
            "io: C2RustUnnamed_1 {",
            // TODO this should be in a different place
            "io: crate::crypto::s2n_aead_cipher_aes_gcm::C2RustUnnamed_2 {",
        )(
            "io: C2RustUnnamed_2 {",
            // TODO this should be in a different place
            "io: crate::crypto::s2n_aead_cipher_aes_gcm::C2RustUnnamed_2 {",
        )
    ]
);

rewrite!(IgnoreResult, ["__STUB_RESULT_IGNORE(",], "let _ = (");

replace!(
    ConstantLiterals,
    [
        ("32767", "i16::MAX"),
        ("65535", "u16::MAX"),
        ("2147483647", "i32::MAX"),
        ("4294967295", "u32::MAX"),
        ("9223372036854775807", "i64::MAX"),
        ("18446744073709551615", "u64::MAX"),
        ("_SC_PAGESIZE", "libc::_SC_PAGESIZE"),
        ("S2N_SUCCESS as libc::c_int", "libc::c_int::ok()"),
        ("S2N_FAILURE as libc::c_int", "libc::c_int::error()"),
    ]
);

replace!(
    Likely,
    [
        ("__STUB_S2N_LIKELY(", "likely!("),
        ("__STUB_S2N_UNLIKELY(", "unlikely!("),
    ]
);

replace!(
    Logic,
    [
        ("__STUB_IMPLIES(", "utils::s2n_safety::implies("),
        ("__STUB_IFF(", "utils::s2n_safety::iff(")
    ]
);

replace!(
    Stddef,
    [
        ("uint8_t", "u8"),
        ("int8_t", "i8"),
        ("uint16_t", "u16"),
        ("int16_t", "i16"),
        ("uint32_t", "u32"),
        ("int32_t", "i32"),
        ("uint64_t", "u64"),
        ("int64_t", "i64"),
        ("ssize_t", "isize"),
        ("size_t", "usize"),
    ]
);

replace!(AsBool, [("as bool", ".as_bool()"),]);

replace!(
    RemoveCasts,
    [
        ("foobarbaz", ""),
        ("as libc::c_ulonglong", ""),
        //("as libc::c_ulong", ""),
        ("as libc::c_longlong", ""),
        ("as libc::c_long", ""),
        //("as libc::c_int", ""),
    ]
);

rewrite!(
    CiphersuiteEncryptionLimit,
    ["encryption_limit: u64::MAX as libc::c_ulong,"],
    "encryption_limit: u64::MAX",
);

struct LiteralCasts {
    indices: Vec<usize>,
}

impl LiteralCasts {
    fn new(_path: &Path, _config: &Arc<Config>) -> Self {
        Self { indices: vec![] }
    }

    fn on_line(&mut self, line: &mut String) -> ControlFlow<()> {
        let nums = &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'][..];
        let casts = &[
            " as libc::c_int",
            " as libc::c_ulonglong",
            " as libc::c_ulong",
            " as libc::longlong",
            " as libc::long",
            /*
            " as i8",
            " as u8",
            " as i16",
            " as u16",
            " as i32",
            " as u32",
            " as i64",
            " as u64",
            */
        ][..];
        let indices = line.rmatch_indices(nums).map(|(idx, _)| idx);
        self.indices.clear();
        self.indices.extend(indices);
        for mut index in self.indices.iter().copied() {
            let match_line = &line[index..];
            let mut m = match_line.trim_start_matches(nums);
            index += match_line.len() - m.len();
            let initial_len = m.len();

            loop {
                let mut found_match = false;
                for cast in casts {
                    if let Some(s) = m.strip_prefix(cast) {
                        m = s;
                        found_match = true;
                    }
                }

                if !found_match {
                    break;
                }
            }

            let len = initial_len - m.len();

            if len == 0 {
                continue;
            }

            let range = index..index + len;
            line.drain(range);
        }
        ControlFlow::Continue(())
    }
}

enum LibRs {
    ProcessingHeader,
    ProcessingBody,
    Disabled,
}

impl LibRs {
    fn new(path: &Path, _config: &Arc<Config>) -> Self {
        if path.file_name().map_or(false, |v| v == "lib.rs") {
            Self::ProcessingHeader
        } else {
            Self::Disabled
        }
    }

    fn on_line(&mut self, line: &mut String) -> ControlFlow<()> {
        match self {
            Self::Disabled => {
                return ControlFlow::Continue(());
            }
            Self::ProcessingHeader => {
                // remove any features, since they're nightly-only
                if line.starts_with("#![feature(") {
                    return ControlFlow::Break(());
                }

                if line.starts_with("#!") || line.is_empty() {
                    return ControlFlow::Continue(());
                }

                line.insert_str(
                    0,
                    r#"
mod api;
pub use api::*;

#[macro_use]
pub mod error {
    pub mod s2n_errno;
    pub use s2n_errno::*;
    pub mod s2n_errno_errors;
    pub use s2n_errno_errors::*;
}
use error::*;

mod libc;
use aws_lc_sys as libcrypto;
"#,
                );
                *self = Self::ProcessingBody;

                ControlFlow::Continue(())
            }
            Self::ProcessingBody => {
                if line == "extern crate libc;" {
                    return ControlFlow::Break(());
                }

                let flatten_export = true;

                if flatten_export {
                    let trimmed = line.trim_start();
                    let Some(module) = trimmed.strip_prefix("pub mod ") else {
                        return ControlFlow::Continue(());
                    };

                    if let Some(top) = module.strip_suffix(" {") {
                        *line = format!("pub use {top}::*;\n{line}");
                        return ControlFlow::Continue(());
                    }

                    let module = module.trim_end_matches(';');

                    line.push_str(&format!("\npub use {module}::*;"));
                }

                ControlFlow::Continue(())
            }
        }
    }
}

struct Prelude {
    enabled: bool,
}

impl Prelude {
    fn new(path: &Path, _config: &Arc<Config>) -> Self {
        Self {
            enabled: !path.file_name().map_or(false, |v| v == "lib.rs"),
        }
    }

    fn on_line(&mut self, line: &mut String) -> ControlFlow<()> {
        if !self.enabled {
            return ControlFlow::Continue(());
        }

        if !self.enabled || line.starts_with("#!") || line.is_empty() {
            return ControlFlow::Continue(());
        }

        // TODO build an import list based on used functions - if we do a wildcard then rustc just
        // spins forever
        line.insert_str(
            0,
            r#"
// TODO remove the * import
use crate::{utils::{s2n_result::Outcome}, *};
"#,
        );
        self.enabled = false;

        ControlFlow::Continue(())
    }
}
