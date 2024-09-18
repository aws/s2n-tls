// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use regex::Regex;
use std::ffi::OsStr;
use std::fs;
use std::fs::read_to_string;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // for all unit tests
    for test_file in fs::read_dir("../tests/unit").unwrap() {
        let test_file = test_file.as_ref().unwrap();
        let test_file_path = test_file.path();

        let is_file = test_file.file_type().unwrap().is_file();
        // filter on .c files. eg. exclude "valgrind.suppressions"
        let is_c_file = test_file_path.extension().unwrap_or(OsStr::new("not_c")) == "c";
        if is_file && is_c_file {
            let lines = read_file_to_vec(&test_file_path);
            process_test_file(test_file_path, lines);
        }
    }
}

// Generates the desired temp file as we parse the actual test file. Then replaces the test file
// with the auto-generated temp file.
fn process_test_file(test_file_path: PathBuf, lines: Vec<String>) {
    let test_file_name = test_file_path.file_name().unwrap().to_str().unwrap();

    // create temp file
    let tmp_filename = format!("tmp_{}", test_file_name);
    let mut tmp_file = File::create(tmp_filename.clone()).unwrap();

    let mut line_idx = 0;
    while line_idx < lines.len() {
        let line = &lines[line_idx];

        // WRITE: the current line
        writeln!(tmp_file, "{}", line).unwrap();

        if match_config_new(line) {
            // if config creation is across two lines, then write both lines before inserting the
            // auto-gen code
            if config_creation_spans_two_lines(&lines, line_idx) {
                let nxt_line = &lines[line_idx + 1];
                // WRITE: config creating spans two lines so write it
                writeln!(tmp_file, "{}", nxt_line).unwrap();

                // increment line_idx since we already wrote the second line
                line_idx += 1;
            }

            // insert auto gen. replacing the actual `config_name` used in test code
            let config_name = get_config_name(line);
            let auto_gen = format!(
                        "EXPECT_SUCCESS(s2n_config_set_cipher_preferences({}, s2n_auto_gen_old_default_security_policy()));",
                        config_name
                    );
            // WRITE: auto-gen
            writeln!(tmp_file, "{}", auto_gen).unwrap();
        }

        // increment to next line
        line_idx += 1;
    }

    println!("Amended file: {:?}", test_file_path);
    fs::rename(tmp_filename, test_file_path.clone()).unwrap();
    Command::new("clang-format")
        .arg("-i")
        .arg(test_file_path)
        .status()
        .unwrap();
}

// agressively match all instance of "s2n_config_new()" to avoid missing
// any instances
fn match_config_new(line: &str) -> bool {
    line.contains("s2n_config_new()")
}

// Extract the config name used in tests.
//
// These are all the occurances of s2n_config_new() which must be handled:
//
// ```
// DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
// struct s2n_config *config = s2n_config_new();
// DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
// EXPECT_NOT_NULL(config = s2n_config_new());
// POSIX_GUARD_PTR(server_config = s2n_config_new());
// POSIX_ENSURE_REF(client_config = s2n_config_new());
// ```
fn get_config_name(line: &str) -> String {
    let config_name = line.trim();

    // remove the end
    //
    // pattern: " = s2n_config_new());"
    // pattern: " = s2n_config_new(), s2n_config_ptr_free);"
    let re = Regex::new(r" = .*").unwrap();
    let config_name: String = re.replace(config_name, "").into_owned();

    // attempt to remove if pattern matches
    //
    // DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
    // struct s2n_config *config = s2n_config_new();
    // DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    let re = Regex::new(r".*struct s2n_config \*").unwrap();
    let config_name: String = re.replace(&config_name, "").into_owned();

    // attempt to remove if pattern matches
    //
    // EXPECT_NOT_NULL(config = s2n_config_new());
    let config_name = config_name.replace("EXPECT_NOT_NULL(", "");

    // attempt to remove if pattern matches
    //
    // POSIX_GUARD_PTR(server_config = s2n_config_new());
    let config_name = config_name.replace("POSIX_GUARD_PTR(", "");

    // attempt to remove if pattern matches
    //
    // POSIX_ENSURE_REF(client_config = s2n_config_new());
    config_name.replace("POSIX_ENSURE_REF(", "")
}

// Detect if config creating spans two lines by checking if `s2n_config_ptr_free`
//
// Attempt to match the following pattern.
// ```
// DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
//         s2n_config_ptr_free);
// ```
//
// Use `starts_with` to avoid a false positive if two configs are declared one after another.
//
// ```
// DEFER_CLEANUP(struct s2n_config *config1 = s2n_config_new(), s2n_config_ptr_free);
// DEFER_CLEANUP(struct s2n_config *config2 = s2n_config_new(), s2n_config_ptr_free);
// ```
fn config_creation_spans_two_lines(lines: &[String], idx: usize) -> bool {
    if let Some(next_line) = lines.get(idx + 1) {
        // pattern: "        s2n_config_ptr_free);"
        if next_line
            // pattern: "s2n_config_ptr_free);"
            .trim()
            .starts_with("s2n_config_ptr_free);")
        {
            return true;
        }
    }

    false
}

fn read_file_to_vec(path: &PathBuf) -> Vec<String> {
    let mut result = Vec::new();
    for line in read_to_string(path).unwrap().lines() {
        result.push(line.to_string());
    }
    result
}
