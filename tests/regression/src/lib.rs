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
    const MAX_DIFF: u64 = 1_000_000; 

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

    fn valgrind_test<F>(test_name: &str, test_body: F) -> Result<(), s2n_tls::error::Error>
    where
        F: FnOnce(&InstrumentationControl) -> Result<(), s2n_tls::error::Error>,
    {
        if !is_running_under_valgrind() {
            let ctrl = InstrumentationControl;
            test_body(&ctrl)
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
    fn run_valgrind_test(test_name: &str) {
        let exe_path = std::env::args().next().unwrap();
        create_dir_all(Path::new("target/cg_artifacts")).unwrap();
        let output_file = format!("target/cg_artifacts/cachegrind_{}.out", test_name);
        let output_command = format!("--cachegrind-out-file={}", &output_file);
        let mut command = Command::new("valgrind");
        command
            .args(["--tool=cachegrind", &output_command, &exe_path, test_name])
            // Ensures that the recursive call is made to the actual harness code block rather than back to this function
            .env_remove("ENABLE_VALGRIND"); 

        println!("Running command: {:?}", command);
        let status = command.status().expect("Failed to execute valgrind");

        if !status.success() {
            panic!("Valgrind failed");
        }

        let annotate_output = Command::new("cg_annotate")
            .arg(&output_file)
            .output()
            .expect("Failed to run cg_annotate");

        if !annotate_output.status.success() {
            panic!("cg_annotate failed");
        }
        create_dir_all(Path::new("target/perf_outputs")).unwrap();
        let annotate_file = format!("target/perf_outputs/{}.annotated.txt", test_name);
        let mut file = File::create(&annotate_file).expect("Failed to create annotation file");
        file.write_all(&annotate_output.stdout)
            .expect("Failed to write annotation file");

        let count = find_instruction_count(&annotate_file)
            .expect("Failed to get instruction count from file");
        // This is temporary code to showcase the future diff functionality, here the code regresses by 10% each time so this test will almost always fail
        let new_count = count + count / 10;
        let diff = new_count - count;
        assert!(diff <= self::MAX_DIFF, "Instruction count difference in {} exceeds the threshold, regression of {} instructions", test_name, diff);
    }

    /// Parses the annotated file for the overall instruction count total
    fn find_instruction_count(file_path: &str) -> Result<u64, io::Error> {
        let path = Path::new(file_path);
        let file = File::open(path)?;
        let reader = io::BufReader::new(file);
        // Example of the line being parsed:
        // "79,278,369 (100.0%)  PROGRAM TOTALS"
        for line in reader.lines() {
            let line = line?;
            if line.contains("PROGRAM TOTALS") {
                if let Some(instructions) = line.split_whitespace().next() {
                    return instructions
                        .replace(',', "")
                        .parse::<u64>()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
                }
            }
        }

        panic!("Failed to find instruction count in annotated file");
    }
}
