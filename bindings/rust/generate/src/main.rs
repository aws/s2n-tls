// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeSet,
    io,
    path::Path,
    sync::{Arc, Mutex},
};

fn main() {
    let out_dir = std::env::args().nth(1).expect("missing sys dir");
    let out_dir = Path::new(&out_dir);

    let functions = FunctionCallbacks::default();

    gen_bindings(
        "#include <s2n.h>",
        &out_dir.join("lib"),
        functions.with_feature(None),
    )
    .allowlist_type("s2n_.*")
    .allowlist_function("s2n_.*")
    .allowlist_var("s2n_.*")
    .generate()
    .unwrap()
    .write_to_file(out_dir.join("src/api.rs"))
    .unwrap();

    gen_bindings(
        "#include \"tls/s2n_quic_support.h\"",
        &out_dir.join("lib"),
        functions.with_feature(Some("quic")),
    )
    .allowlist_function("s2n_.*quic.*")
    .allowlist_function("s2n_.*secret_callback.*")
    .allowlist_function("s2n_error_get_alert")
    .blocklist_type("s2n_config")
    .blocklist_type("s2n_connection")
    .raw_line("use crate::api::*;\n")
    .generate()
    .unwrap()
    .write_to_file(out_dir.join("src/quic.rs"))
    .unwrap();

    gen_bindings(
        "#include \"tls/s2n_internal.h\"",
        &out_dir.join("lib"),
        functions.with_feature(Some("internal")),
    )
    // any new internal functions need to be added here
    .allowlist_function("s2n_.*")
    .blocklist_type("s2n_config")
    .blocklist_type("s2n_connection")
    .raw_line("use crate::api::*;\n")
    .generate()
    .unwrap()
    .write_to_file(out_dir.join("src/internal.rs"))
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

fn gen_bindings(entry: &str, s2n_dir: &Path, functions: FunctionCallbacks) -> bindgen::Builder {
    bindgen::Builder::default()
        .use_core()
        .layout_tests(true)
        .detect_include_paths(true)
        .size_t_is_usize(true)
        .rustfmt_bindings(true)
        .header_contents("s2n-sys.h", entry)
        .enable_function_attribute_detection()
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .rust_target(bindgen::RustTarget::Stable_1_40)
        // only export s2n-related stuff
        .blocklist_type("iovec")
        .blocklist_type("FILE")
        .blocklist_type("_IO_.*")
        .blocklist_type("__.*")
        .blocklist_type("fpos_t")
        // rust can't access thread-local variables
        // https://github.com/rust-lang/rust/issues/29594
        .blocklist_item("s2n_errno")
        .raw_line(COPYRIGHT)
        .raw_line(PRELUDE)
        .ctypes_prefix("::libc")
        .parse_callbacks(Box::new(functions))
        .clang_arg(format!("-I{}/api", s2n_dir.display()))
        .clang_arg(format!("-I{}", s2n_dir.display()))
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
        // don't include tests
        if file.starts_with("tests") {
            continue;
        }
        writeln!(o, "    {:?},", Path::new("lib").join(file).display())?;
    }
    writeln!(o, "]")?;
    Ok(())
}

type SharedBTreeSet<T> = Arc<Mutex<BTreeSet<T>>>;

#[derive(Clone, Debug, Default)]
struct FunctionCallbacks {
    feature: Arc<Mutex<Option<&'static str>>>,
    types: SharedBTreeSet<String>,
    functions: SharedBTreeSet<(Option<&'static str>, String)>,
}

impl FunctionCallbacks {
    fn with_feature(&self, feature: Option<&'static str>) -> Self {
        *self.feature.lock().unwrap() = feature;
        self.clone()
    }

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
                "s2n_cert_public_key",
                "s2n_cert_chain_and_key",
                "s2n_cert_private_key",
                "s2n_cert_tiebreak_callback",
                "s2n_client_hello",
                "s2n_client_hello_fn",
                "s2n_clock_time_nanoseconds",
                "s2n_config",
                "s2n_connection",
                "s2n_early_data_cb",
                "s2n_key_log_fn",
                "s2n_mem_cleanup_callback",
                "s2n_mem_free_callback",
                "s2n_mem_init_callback",
                "s2n_mem_malloc_callback",
                "s2n_offered_early_data",
                "s2n_offered_psk",
                "s2n_offered_psk_list",
                "s2n_offered_psk_new",
                "s2n_pkey",
                "s2n_psk",
                "s2n_psk_selection_callback",
                "s2n_rand_cleanup_callback",
                "s2n_rand_init_callback",
                "s2n_rand_mix_callback",
                "s2n_rand_seed_callback",
                "s2n_recv_fn",
                "s2n_secret_cb",
                "s2n_send_fn",
                "s2n_session_ticket",
                "s2n_session_ticket_fn",
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
        let iter = functions.iter();
        for (feature, function) in iter {
            // don't generate tests for types
            if types.contains(function) {
                continue;
            }

            // don't generate a test if it's enabled without a feature
            if feature.is_some() && functions.contains(&(None, function.to_string())) {
                continue;
            }

            writeln!(o, "#[test]")?;

            // if the function is behind a feature, gate it with `cfg`
            if let Some(feature) = feature {
                writeln!(o, "#[cfg(feature = {:?})]", feature)?;
            };

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
        variant_name: &str,
        _variant_value: bindgen::callbacks::EnumVariantValue,
    ) -> Option<String> {
        let name = name.unwrap_or("");
        if name.starts_with("s2n_") {
            self.types.lock().unwrap().insert(name.to_owned());
        }

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
            .trim_start_matches("S2N_CLIENT_HELLO_CB_")
            .trim_start_matches("S2N_TLS_SIGNATURE_")
            .trim_start_matches("S2N_TLS_HASH_")
            .trim_start_matches("S2N_PSK_HMAC_")
            .trim_start_matches("S2N_PSK_MODE_")
            .trim_start_matches("S2N_ASYNC_PKEY_VALIDATION_")
            .trim_start_matches("S2N_ASYNC_")
            .trim_start_matches("S2N_EARLY_DATA_STATUS_")
            // match everything else
            .trim_start_matches("S2N_");

        Some(variant_name.to_owned())
    }

    fn item_name(&self, name: &str) -> Option<String> {
        if name.starts_with("s2n_") {
            let feature = *self.feature.lock().unwrap();
            self.functions
                .lock()
                .unwrap()
                .insert((feature, name.to_owned()));
        }
        None
    }
}
