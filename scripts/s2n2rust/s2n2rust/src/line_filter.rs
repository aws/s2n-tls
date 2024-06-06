use super::*;
use core::ops::ControlFlow;
use glob::glob;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};

pub fn run(sh: &Shell) -> Result {
    std::env::set_current_dir(sh.current_dir())?;
    for file in glob("src/**/*.rs")?.flatten() {
        let _ = process_file(&file);
    }
    Ok(())
}

fn process_file(path: &Path) -> Result {
    let file_name = path
        .file_name()
        .map(|v| v.to_string_lossy().to_string())
        .unwrap_or_default();

    if ["errno.rs"].contains(&file_name.as_str()) {
        return Ok(());
    }

    let original = path.with_extension("bkup");
    if !original.exists() {
        std::fs::copy(path, &original)?;
    }

    let file = File::open(&original)?;
    let file = BufReader::new(file);
    let out = File::create(path)?;
    let mut out = BufWriter::new(out);

    process_text(path, file, &mut out)?;

    out.flush()?;
    Ok(())
}

fn process_text(path: &Path, file: impl BufRead, out: &mut impl Write) -> Result {
    let mut processors = Processors::new(path);
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
            fn new(path: &Path) -> Self {
                Self {
                    $(
                        $lower: <$Upper>::new(path),
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
        librs: LibRs,
        prelude: Prelude,
        extern_block: ExternBlock,
    }
);

/// Removes any redundant imported constants
struct ConstFilter {}

impl ConstFilter {
    fn new(_path: &Path) -> Self {
        Self {}
    }

    fn on_line(&mut self, line: &mut String) -> ControlFlow<()> {
        let trimmed = line.trim_start();
        let Some(candidate) = trimmed.strip_prefix("pub const ") else {
            return ControlFlow::Continue(());
        };
        for prefix in ["S2N_ERR_", "_SC_", "S2N_SUCCESS", "S2N_FAILURE"] {
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
    fn new(_path: &Path) -> Self {
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
            "int8_t",
            "uint8_t",
            "int16_t",
            "uint16_t",
            "int32_t",
            "uint32_t",
            "int64_t",
            "uint64_t",
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
struct ExternTypes {}

impl ExternTypes {
    fn new(_path: &Path) -> Self {
        Self {}
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

        match ty {
            "s2n_async_pkey_op" => {
                line.clear();
                line.push_str("use crate::tls::s2n_async_pkey::s2n_async_pkey_op;");
            }
            "s2n_connection" => {
                line.clear();
                line.push_str("use crate::tls::s2n_connection::s2n_connection;");
            }
            "s2n_map" => {
                line.clear();
                line.push_str("use crate::utils::s2n_map::s2n_map;");
            }
            ty if ty.starts_with("s2n_") => {
                println!("UNHANDLED EXTERN TYPE: {ty}");
                *line = format!("use crate::prelude::{ty};");
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
    fn new(_path: &Path) -> Self {
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
}

impl OwningStruct {
    fn new(path: &Path) -> Self {
        Self {
            pending_use: None,
            file_name: path
                .file_stem()
                .map(|v| v.to_string_lossy())
                .unwrap_or_default()
                .to_string(),
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

        let Some(name) = line.strip_prefix("pub struct ") else {
            return ControlFlow::Continue(());
        };

        let name = name.trim_end_matches(" {").trim_end_matches("<'a>");

        // if the file doesn't "own" the struct then remove it
        if name == "s2n_result" || !name.starts_with(&self.file_name) {
            if !name.starts_with("C2RustUnnamed") {
                self.pending_use = Some(match name {
                    "s2n_result" => "\nuse crate::errno::s2n_result;\n".to_string(),
                    "iovec" | "msghdr" | "cmsghdr" | "timespec" | "stat" => {
                        format!("\nuse libc::{name};\n")
                    }
                    _ if name.starts_with("s2n_") => format!("\nuse crate::{name};\n"),
                    _ => format!("\nuse crate::libcrypto::{name};\n"),
                });
            }
            *line = format!("struct __CLEANUP__{name} {{");
        }

        ControlFlow::Continue(())
    }
}

macro_rules! rewrite {
    ($name:ident, [$($pat:expr),* $(,)?], $out:expr) => {
        struct $name {}

        impl $name {
            fn new(_path: &Path) -> Self {
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
            fn new(_path: &Path) -> Self {
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

/// Removes #[no_mangle] attributes
struct NoMangle {}

impl NoMangle {
    fn new(_path: &Path) -> Self {
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
        ("__STUB_RESULT_OK()", "s2n_result::ok()"),
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
    "crate::errno::memmove("
);

rewrite!(IgnoreResult, ["__STUB_RESULT_IGNORE(",], "let _ = (");

replace!(
    ConstantLiterals,
    [
        ("4294967295", "u32::MAX"),
        ("9223372036854775807", "u64::MAX"),
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
        ("__STUB_IMPLIES(", "errno::implies("),
        ("__STUB_IFF(", "errno::iff(")
    ]
);

replace!(
    Stddef,
    [
        ("int8_t", "i8"),
        ("uint8_t", "u8"),
        ("int16_t", "i16"),
        ("uint16_t", "u16"),
        ("int32_t", "i32"),
        ("uint32_t", "u32"),
        ("int64_t", "i64"),
        ("uint64_t", "u64"),
        ("size_t", "usize"),
    ]
);

replace!(AsBool, [("as bool", "!= 0"),]);

enum LibRs {
    ProcessingHeader,
    ProcessingBody,
    Disabled,
}

impl LibRs {
    fn new(path: &Path) -> Self {
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
#[macro_use]
mod errno;

use aws_lc_sys as libcrypto;
"#,
                );
                *self = Self::ProcessingBody;

                ControlFlow::Continue(())
            }
            Self::ProcessingBody => {
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

                ControlFlow::Continue(())
            }
        }
    }
}

struct Prelude {
    enabled: bool,
}

impl Prelude {
    fn new(path: &Path) -> Self {
        Self {
            enabled: !path.file_name().map_or(false, |v| v == "lib.rs"),
        }
    }

    fn on_line(&mut self, line: &mut String) -> ControlFlow<()> {
        if !self.enabled || line.starts_with("#!") || line.is_empty() {
            return ControlFlow::Continue(());
        }

        // TODO build an import list based on used functions - if we do a wildcard then rustc just
        // spins forever
        line.insert_str(0, "use crate::errno::Outcome as _;\nuse libc::memset;\n");
        self.enabled = false;

        ControlFlow::Continue(())
    }
}
