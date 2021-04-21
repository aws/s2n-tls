// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use bindgen::CodegenConfig;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::{io, path::Path};

fn main() {
    let out_dir = std::env::args().nth(1).expect("missing sys dir");
    let out_dir = Path::new(&out_dir);

    gen_bindings("#include <s2n.h>", &out_dir.join("lib"))
        .allowlist_type("s2n_.*")
        .allowlist_function("s2n_.*")
        .allowlist_var("s2n_.*")
        .generate()
        .unwrap()
        .write_to_file(out_dir.join("src/api.rs"))
        .unwrap();

    gen_bindings("#include \"tls/s2n_quic_support.h\"", &out_dir.join("lib"))
        .allowlist_function("s2n_.*quic.*")
        .allowlist_function("s2n_.*secret_callback.*")
        .blocklist_type("s2n_config")
        .blocklist_type("s2n_connection")
        .raw_line("use crate::api::*;\n")
        .generate()
        .unwrap()
        .write_to_file(out_dir.join("src/quic.rs"))
        .unwrap();

    let functions = FunctionCallbacks::default();

    gen_bindings("#include <s2n.h>", &out_dir.join("lib"))
        .allowlist_function("s2n_.*")
        .with_codegen_config(CodegenConfig::FUNCTIONS)
        .parse_callbacks(Box::new(functions.clone()))
        .generate()
        .unwrap();

    functions.tests(&out_dir.join("src/tests.rs")).unwrap();

    gen_files(&out_dir.join("lib"), &out_dir.join("files.rs")).unwrap();
}

const COPYRIGHT: &str = r#"
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
"#;

const PRELUDE: &str = r#"
#![allow(unused_imports, non_camel_case_types)]

use libc::{iovec, FILE};
"#;

fn gen_bindings(entry: &str, s2n_dir: &Path) -> bindgen::Builder {
    let builder = bindgen::Builder::default()
        .use_core()
        .layout_tests(true)
        .detect_include_paths(true)
        .size_t_is_usize(true)
        .rustfmt_bindings(true)
        .header_contents("s2n-sys.h", entry)
        .enable_function_attribute_detection()
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: true,
        })
        .rust_target(bindgen::RustTarget::Stable_1_40)
        // only export s2n-related stuff
        .blocklist_type("iovec")
        .blocklist_type("FILE")
        .blocklist_type("_IO_.*")
        .blocklist_type("__.*")
        // rust can't access thread-local variables
        // https://github.com/rust-lang/rust/issues/29594
        .blocklist_item("s2n_errno")
        .rustified_enum("s2n_.*")
        .raw_line(COPYRIGHT)
        .raw_line(PRELUDE)
        .ctypes_prefix("::libc")
        .parse_callbacks(Box::new(S2nCallbacks::default()))
        .clang_arg(format!("-I{}/api", s2n_dir.display()))
        .clang_arg(format!("-I{}", s2n_dir.display()));
    builder
}

fn gen_files(input: &Path, out: &Path) -> io::Result<()> {
    use io::Write;

    let mut files = std::fs::File::create(out)?;
    let mut o = io::BufWriter::new(&mut files);

    let pattern = format!("{}/**/*.c", input.display());

    writeln!(o, "{}", COPYRIGHT)?;
    writeln!(o, "[")?;
    for file in glob::glob(&pattern).unwrap() {
        let file = file.unwrap();
        let file = file.strip_prefix(input).unwrap();
        writeln!(o, "    {:?},", Path::new("lib").join(file).display())?;
    }
    writeln!(o, "]")?;
    Ok(())
}

#[derive(Debug, Default)]
struct S2nCallbacks;

impl bindgen::callbacks::ParseCallbacks for S2nCallbacks {
    fn enum_variant_name(
        &self,
        _enum_name: Option<&str>,
        variant_name: &str,
        _variant_value: bindgen::callbacks::EnumVariantValue,
    ) -> Option<String> {
        use heck::CamelCase;

        if !variant_name.starts_with("S2N_") {
            return None;
        }

        let variant_name = variant_name
            .trim_start_matches("S2N_ERR_T_")
            .trim_start_matches("S2N_EXTENSION_")
            // keep the LEN_ so it's a valid identifier
            .trim_start_matches("S2N_TLS_MAX_FRAG_")
            .trim_start_matches("S2N_ALERT_")
            .trim_start_matches("S2N_CT_SUPPORT_")
            .trim_start_matches("S2N_STATUS_REQUEST_")
            .trim_start_matches("S2N_CERT_AUTH_")
            // match everything else
            .trim_start_matches("S2N_");

        Some(variant_name.to_camel_case())
    }
}

#[derive(Clone, Debug, Default)]
struct FunctionCallbacks {
    types: Arc<Mutex<BTreeSet<String>>>,
    functions: Arc<Mutex<BTreeSet<String>>>,
}

impl FunctionCallbacks {
    fn tests(&self, out: &Path) -> io::Result<()> {
        use io::Write;
        let functions = self.functions.lock().unwrap();
        let mut types = self.types.lock().unwrap();

        // bindgen doesn't have the ability to filter out type aliases
        // so we'll need to have a list of them here for now
        types.extend(
            [
                "s2n_async_pkey_fn",
                "s2n_async_pkey_op",
                "s2n_cache_delete_callback",
                "s2n_cache_retrieve_callback",
                "s2n_cache_store_callback",
                "s2n_cert",
                "s2n_cert_chain_and_key",
                "s2n_cert_private_key",
                "s2n_cert_tiebreak_callback",
                "s2n_client_hello",
                "s2n_client_hello_fn",
                "s2n_clock_time_nanoseconds",
                "s2n_config",
                "s2n_connection",
                "s2n_key_log_fn",
                "s2n_mem_cleanup_callback",
                "s2n_mem_free_callback",
                "s2n_mem_init_callback",
                "s2n_mem_malloc_callback",
                "s2n_pkey",
                "s2n_rand_cleanup_callback",
                "s2n_rand_init_callback",
                "s2n_rand_mix_callback",
                "s2n_rand_seed_callback",
                "s2n_recv_fn",
                "s2n_send_fn",
                "s2n_stacktrace",
                "s2n_verify_host_fn",
            ]
            .iter()
            .copied()
            .map(String::from),
        );

        let mut tests = std::fs::File::create(out)?;
        let mut o = io::BufWriter::new(&mut tests);

        writeln!(o, "{}", COPYRIGHT)?;
        for function in functions.difference(&types) {
            writeln!(o, "#[test]")?;
            writeln!(o, "fn {} () {{", function)?;
            writeln!(o, "    let ptr = crate::{} as *const ();", function)?;
            writeln!(o, "    assert!(!ptr.is_null());")?;
            writeln!(o, "}}")?;
            writeln!(o)?;
        }

        Ok(())
    }
}

impl bindgen::callbacks::ParseCallbacks for FunctionCallbacks {
    fn enum_variant_name(
        &self,
        name: Option<&str>,
        _original_variant_name: &str,
        _variant_value: bindgen::callbacks::EnumVariantValue,
    ) -> Option<String> {
        let name = name.unwrap_or("");
        if name.starts_with("s2n_") {
            self.types.lock().unwrap().insert(name.to_owned());
        }
        None
    }

    fn item_name(&self, name: &str) -> Option<String> {
        if name.starts_with("s2n_") {
            self.functions.lock().unwrap().insert(name.to_owned());
        }
        None
    }
}
