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

#[cfg(test)]
mod tests {
    use super::*;
    use crabgrind as cg;
    use s2n_tls::testing::TestPair;
    use std::{
        env,
        fs::{create_dir_all, File},
        io::{self, BufRead, Write},
        path::Path,
        process::Command,
    };

    /// Configurable threshold for regression testing.
    /// Tests will fail if the instruction count difference is greater than the value of this constant.
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

    /// Function to get the test suffix from environment variables. If the var is not set, it defaults to curr.
    fn get_test_suffix() -> String {
        env::var("TEST_SUFFIX").unwrap_or_else(|_| "curr".to_string())
    }

    /// Function to determine if diff mode is enabled.
    fn is_diff_mode() -> bool {
        env::var("DIFF_MODE").is_ok()
    }

    fn valgrind_test<F>(test_name: &str, test_body: F) -> Result<(), s2n_tls::error::Error>
    where
        F: FnOnce(&InstrumentationControl) -> Result<(), s2n_tls::error::Error>,
    {
        let suffix = get_test_suffix();
        if !is_running_under_valgrind() {
            if is_diff_mode() {
                run_diff_test(test_name); 
                Ok(())
            } else {
                let ctrl = InstrumentationControl;
                test_body(&ctrl)
            }
        } else {
            run_valgrind_test(test_name, &suffix);
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
            // Example usage with RSA keypair (default)
            let keypair_rsa = CertKeyPair::default();
            let config = set_config(&security::DEFAULT_TLS13, keypair_rsa)?;
            // Create a pair (client + server) using that config, start handshake measurement
            let mut pair = TestPair::from_config(&config);
            // Assert a successful handshake
            ctrl.start_instrumentation();
            assert!(pair.handshake().is_ok());
            ctrl.stop_instrumentation();
            Ok(())
        })
        .unwrap();
    }

    /// Function to run specified test using valgrind
    fn run_valgrind_test(test_name: &str, suffix: &str) {
        let exe_path = std::env::args().next().unwrap();
        let output_file = create_output_file_path(test_name, suffix);
        let command = build_valgrind_command(&exe_path, test_name, &output_file);
        
        println!("Running command: {:?}", command);
        execute_command(command);
        
        let annotate_output = run_cg_annotate(&output_file);
        save_annotate_output(&annotate_output, suffix, test_name);
        
        let count = find_instruction_count(&annotate_output)
            .expect("Failed to get instruction count from file");

        println!("Instruction count for {}: {}", test_name, count);
    }
    /// Creates the path for the unannotated output file.
    fn create_output_file_path(test_name: &str, suffix: &str) -> String {
        create_dir_all(Path::new("target/cg_artifacts")).unwrap();
        format!("target/cg_artifacts/cachegrind_{}_{}.out", test_name, suffix)
    }
    /// Builds the valgrind command.
    fn build_valgrind_command(exe_path: &str, test_name: &str, output_file: &str) -> Command {
        let output_command = format!("--cachegrind-out-file={}", output_file);
        let mut command = Command::new("valgrind");
        command
            .args(["--tool=cachegrind", &output_command, exe_path, test_name])
            .env_remove("ENABLE_VALGRIND");
        command
    }
    /// Executes the given command.
    fn execute_command(mut command: Command) {
        let status = command.status().expect("Failed to execute valgrind");
        if !status.success() {
            panic!("Valgrind failed");
        }
    }
    /// Runs the cg_annotate command on the output file.
    fn run_cg_annotate(output_file: &str) -> std::process::Output {
        let annotate_output = Command::new("cg_annotate")
            .arg(output_file)
            .output()
            .expect("Failed to run cg_annotate");
        if !annotate_output.status.success() {
            panic!("cg_annotate failed");
        }
        annotate_output
    }
    /// Saves the annotated output to prev, curr, or diff accordingly
    fn save_annotate_output(output: &std::process::Output, suffix: &str, test_name: &str) {
        let directory = format!("target/perf_outputs/{}", suffix);
        create_dir_all(Path::new(&directory)).unwrap();
        let annotate_file = format!("target/perf_outputs/{}/{}_{}.annotated.txt", suffix, test_name, suffix);
        let mut file = File::create(&annotate_file).expect("Failed to create annotation file");
        file.write_all(&output.stdout)
            .expect("Failed to write annotation file");
    }
    /// Function to run the diff test using valgrind, only called when diff mode is set
    fn run_diff_test(test_name: &str) {
        let (prev_file, curr_file) = get_diff_files(test_name);
        ensure_diff_files_exist(&prev_file, &curr_file);
        
        let diff_output = run_cg_annotate_diff(&prev_file, &curr_file);
        save_diff_output(&diff_output, test_name);
        
        let diff = find_instruction_count(&diff_output)
            .expect("Failed to parse cg_annotate --diff output");

        assert_diff_within_threshold(diff, test_name);
    }
    /// Retrieves the file paths for the diff test.
    fn get_diff_files(test_name: &str) -> (String, String) {
        (
            format!("target/cg_artifacts/cachegrind_{}_prev.out", test_name),
            format!("target/cg_artifacts/cachegrind_{}_curr.out", test_name),
        )
    }
    /// Ensures that the required performance files exist to use diff functionality
    fn ensure_diff_files_exist(prev_file: &str, curr_file: &str) {
        if !Path::new(prev_file).exists() || !Path::new(curr_file).exists() {
            panic!("Required cachegrind files not found: {} or {}", prev_file, curr_file);
        }
    }
    /// Runs the cg_annotate diff command to parse already generated performance files and compare them
    fn run_cg_annotate_diff(prev_file: &str, curr_file: &str) -> std::process::Output {
        let diff_output = Command::new("cg_annotate")
            .args(["--diff", prev_file, curr_file])
            .output()
            .expect("Failed to run cg_annotate --diff");
        if !diff_output.status.success() {
            panic!("cg_annotate --diff failed");
        }
        diff_output
    }
    /// Saves the output of the cg_annotate diff command to a file.
    fn save_diff_output(output: &std::process::Output, test_name: &str) {
        create_dir_all(Path::new("target/perf_outputs/diff")).unwrap();
        let diff_file = format!("target/perf_outputs/diff/{}_diff.annotated.txt", test_name);
        let mut file = File::create(&diff_file).expect("failed to create diff annotation file");
        file.write_all(&output.stdout)
            .expect("Failed to write diff annotation file");
    }
    /// Asserts that the instruction count difference is within the threshold.
    fn assert_diff_within_threshold(diff: i64, test_name: &str) {
        assert!(
            diff <= MAX_DIFF,
            "Instruction count difference in {} exceeds the threshold, regression of {} instructions",
            test_name,
            diff,
        );
    }

    /// Parses the annotated file for the overall instruction count total.
    fn find_instruction_count(output: &std::process::Output) -> Result<i64, io::Error> {
        let reader = io::BufReader::new(&output.stdout[..]);
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
