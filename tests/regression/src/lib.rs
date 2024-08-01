// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{
    config::Builder,
    security,
    testing::{CertKeyPair, InsecureAcceptAllCertificatesHandler},
};
type Error = s2n_tls::error::Error;

/// Function to create default config with specified parameters.
pub fn set_config(
    cipher_prefs: &security::Policy,
    keypair: CertKeyPair,
) -> Result<s2n_tls::config::Config, Error> {
    let mut builder = Builder::new();
    builder
        .set_security_policy(cipher_prefs)
        .expect("Unable to set config cipher preferences");
    builder
        .set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})
        .expect("Unable to set a host verify callback.");
    builder
        .load_pem(keypair.cert(), keypair.key())
        .expect("Unable to load cert/pem");
    builder.trust_pem(keypair.cert()).expect("load cert pem");
    builder.build()
}

pub mod git {
    use std::process::Command;

    pub fn get_current_commit_hash() -> String {
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("Failed to get commit hash");

        if !output.status.success() {
            panic!("Git command failed");
        }

        String::from_utf8(output.stdout)
            .expect("Invalid UTF-8 in commit hash")
            .trim()
            .to_string()
    }

    pub fn is_commit_in_log(file: &str) -> bool {
        let commit = extract_commit_hash(file);
        let output = Command::new("git")
            .args(["log", "--pretty=format:%H"])
            .output()
            .expect("Failed to execute git log");
        let log = String::from_utf8(output.stdout).expect("Invalid UTF-8 in git log output");
        log.lines().any(|line| line == commit)
    }

    pub fn is_older_commit(file1: &str, file2: &str) -> bool {
        let commit1 = extract_commit_hash(file1);
        let commit2 = extract_commit_hash(file2);
        let output = Command::new("git")
            .args(["merge-base", "--is-ancestor", &commit1, &commit2])
            .status()
            .expect("Failed to execute git merge-base");
        output.success()
    }

    pub fn extract_commit_hash(file: &str) -> String {
        // input: "target/$commit_id/test_name.raw"
        // output: "$commit_id"
        file.split("target/")
            .nth(1)
            .and_then(|s| s.split('/').next())
            .map(|s| s.to_string())
            .unwrap_or_default() // This will return an empty string if the Option is None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crabgrind as cg;
    use s2n_tls::testing::TestPair;
    use std::{
        env,
        fs::{create_dir_all, write},
        io::{self, BufRead},
        path::Path,
        process::{Command, Output},
    };

    const MAX_DIFF: i64 = 1_000;

    struct InstrumentationControl;

    impl InstrumentationControl {
        fn stop_instrumentation(&self) {
            cg::cachegrind::stop_instrumentation();
        }

        fn start_instrumentation(&self) {
            cg::cachegrind::start_instrumentation();
        }
    }

    /// Environment variable to determine whether to run under valgrind or solely test functionality.
    fn is_running_under_valgrind() -> bool {
        env::var("ENABLE_VALGRIND").is_ok()
    }

    /// Function to determine if diff mode is enabled, runs diff assertion if it is.
    fn is_diff_mode() -> bool {
        env::var("DIFF_MODE").is_ok()
    }

    fn valgrind_test<F>(test_name: &str, test_body: F) -> Result<(), s2n_tls::error::Error>
    where
        F: FnOnce(&InstrumentationControl) -> Result<(), s2n_tls::error::Error>,
    {
        if !is_running_under_valgrind() {
            if is_diff_mode() {
                assert_performance_diff(test_name);
                Ok(())
            } else {
                let ctrl = InstrumentationControl;
                test_body(&ctrl)
            }
        } else {
            run_valgrind_test(test_name);
            Ok(())
        }
    }

    /// Test to create new config, set security policy, host_callback information, load/trust certs, and build config.
    #[test]
    fn test_set_config() {
        valgrind_test("test_set_config", |ctrl| {
            ctrl.stop_instrumentation();
            ctrl.start_instrumentation();
            let keypair_rsa = CertKeyPair::default();
            let _config =
                set_config(&security::DEFAULT_TLS13, keypair_rsa).expect("Failed to build config");
            Ok(())
        })
        .unwrap();
    }
    /// Test which creates a TestPair from config using `rsa_4096_sha512`. Only measures a pair handshake.
    #[test]
    fn test_rsa_handshake() {
        valgrind_test("test_rsa_handshake", |ctrl| {
            ctrl.stop_instrumentation();
            let keypair_rsa = CertKeyPair::default();
            let config = set_config(&security::DEFAULT_TLS13, keypair_rsa)?;
            let mut pair = TestPair::from_config(&config);
            ctrl.start_instrumentation();
            assert!(pair.handshake().is_ok());
            ctrl.stop_instrumentation();
            Ok(())
        })
        .unwrap();
    }

    fn run_valgrind_test(test_name: &str) {
        let exe_path = std::env::args().next().unwrap();
        let commit_hash = git::get_current_commit_hash();
        let output_file = create_raw_profile_path(test_name, &commit_hash);
        let command = build_valgrind_command(&exe_path, test_name, &output_file);

        println!("Running command: {:?}", command);
        execute_command(command);

        let annotate_output = run_annotation(&output_file);
        write_to_file(
            &create_annotated_profile_path(test_name, &commit_hash),
            &annotate_output,
        );

        let count = find_instruction_count(&annotate_output)
            .expect("Failed to get instruction count from file");

        println!("Instruction count for {test_name}: {count}");
    }

    fn create_raw_profile_path(test_name: &str, commit_hash: &str) -> String {
        let new_dir = format!("target/{commit_hash}");
        create_dir_all(Path::new(&new_dir)).unwrap();
        format!("{new_dir}/{test_name}.raw")
    }

    fn create_annotated_profile_path(test_name: &str, commit_hash: &str) -> String {
        let new_dir = format!("target/{commit_hash}");
        create_dir_all(Path::new(&new_dir)).unwrap();
        format!("{new_dir}/{test_name}.annotated")
    }

    fn build_valgrind_command(exe_path: &str, test_name: &str, output_file: &str) -> Command {
        let output_command = format!("--cachegrind-out-file={output_file}");
        let mut command = Command::new("valgrind");
        command
            .args(["--tool=cachegrind", &output_command, exe_path, test_name])
            .env_remove("ENABLE_VALGRIND");
        command
    }

    fn execute_command(mut command: Command) -> Output {
        let output = command.output().expect("Failed to execute command");
        if !output.status.success() {
            panic!("Command failed: {:?}", output);
        }
        output
    }

    fn run_annotation(output_file: &str) -> String {
        let annotate_output = Command::new("cg_annotate")
            .arg(output_file)
            .output()
            .expect("Failed to run cg_annotate");
        if !annotate_output.status.success() {
            panic!("cg_annotate failed");
        }
        String::from_utf8(annotate_output.stdout).expect("Invalid UTF-8 in cg_annotate output")
    }

    fn write_to_file(path: &str, content: &str) {
        write(path, content).expect("Failed to write to file");
    }

    fn assert_performance_diff(test_name: &str) {
        let (prev_file, curr_file) = find_and_validate_diff_files(test_name);
        let diff_output = run_diff_annotation(&prev_file, &curr_file);
        write_to_file(&create_diff_profile_path(test_name), &diff_output);

        let diff = find_instruction_count(&diff_output)
            .expect("Failed to parse cg_annotate --diff output");
        assert_diff_within_threshold(diff, test_name);
    }

    fn find_and_validate_diff_files(test_name: &str) -> (String, String) {
        let annotated_files = find_annotated_files(test_name);
        let file_len = annotated_files.len();
        if file_len != 2 {
            panic!("Expected exactly 2 annotated files for {test_name}, found {file_len}");
        }

        let file1 = &annotated_files[0];
        let file2 = &annotated_files[1];

        if !git::is_commit_in_log(file1) || !git::is_commit_in_log(file2) {
            let first_hash = git::extract_commit_hash(file1);
            let second_hash = git::extract_commit_hash(file2);
            panic!(
                "One or both commit hashes are not in the git log: {first_hash} or {second_hash}"
            );
        }

        let (old_file, new_file) = if git::is_older_commit(file1, file2) {
            (file1.clone(), file2.clone())
        } else {
            (file2.clone(), file1.clone())
        };

        (old_file, new_file)
    }

    fn find_annotated_files(test_name: &str) -> Vec<String> {
        let pattern = format!("target/**/*{test_name}.raw");
        glob::glob(&pattern)
            .expect("Failed to read glob pattern")
            .filter_map(Result::ok)
            .map(|path| path.to_string_lossy().into_owned())
            .collect()
    }

    fn run_diff_annotation(prev_file: &str, curr_file: &str) -> String {
        let diff_output = Command::new("cg_annotate")
            .args(["--diff", prev_file, curr_file])
            .output()
            .expect("Failed to run cg_annotate --diff");
        if !diff_output.status.success() {
            panic!("cg_annotate --diff failed");
        }
        String::from_utf8(diff_output.stdout).expect("Invalid UTF-8 in cg_annotate --diff output")
    }

    fn create_diff_profile_path(test_name: &str) -> String {
        create_dir_all(Path::new("target/diff")).unwrap();
        format!("target/diff/{test_name}.diff")
    }

    fn assert_diff_within_threshold(diff: i64, test_name: &str) {
        assert!(
            diff <= MAX_DIFF,
            "Instruction count difference in {test_name} exceeds the threshold, regression of {diff} instructions. 
            Check the annotated output logs in target/$commit_id/{test_name}.annotated for debug information"
        );
    }

    /// Parses the annotated file for the overall instruction count total.
    pub fn find_instruction_count(output: &str) -> Result<i64, io::Error> {
        let reader = io::BufReader::new(output.as_bytes());
        // Example of the line being parsed:
        // "79,278,369 (100.0%)  PROGRAM TOTALS"
        for line in reader.lines() {
            let line = line?;
            if line.contains("PROGRAM TOTALS") {
                if let Some(instructions) = line.split_whitespace().next() {
                    return instructions
                        .replace(',', "")
                        .parse::<i64>()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
                }
            }
        }
        panic!("Failed to find instruction count in annotated file");
    }
}
