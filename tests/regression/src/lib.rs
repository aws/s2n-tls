// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use s2n_tls::{config::Builder, security, testing::{CertKeyPair, InsecureAcceptAllCertificatesHandler}};
type Error = s2n_tls::error::Error;



// Function to create default config with specified parameters
pub fn set_config(
    cipher_prefs: &security::Policy,
    keypair: CertKeyPair
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
    use std::env;
    use std::process::Command;

    const COST: u64 = 1_000_000; //configurable threshold for regression
    // environment variable to determine whether to run under valgrind or solely test functionality
    fn is_running_under_valgrind() -> bool {
        env::var("VALGRIND").is_ok()
    }
    //test to create new config, set security policy, host_callback information, load/trust certs, and build config
    #[test]
    fn test_set_config() -> Result<(), s2n_tls::error::Error> {
        if !is_running_under_valgrind() {
            cg::cachegrind::stop_instrumentation();
            cg::cachegrind::start_instrumentation();
            let keypair_rsa = CertKeyPair::default();
            let _config = set_config(&security::DEFAULT_TLS13, keypair_rsa).expect("Failed to build config");
            return Ok(());
        }
        run_valgrind_test("test_set_config");
        Ok(())
    }

    #[test]
    fn test_rsa_handshake() -> Result<(), s2n_tls::error::Error> {
        if !is_running_under_valgrind() {
            cg::cachegrind::stop_instrumentation();
            // Example usage with RSA keypair (default)
            let keypair_rsa = CertKeyPair::default();
            let config = set_config(&security::DEFAULT_TLS13, keypair_rsa)?;
            // Create a pair (client + server) using that config, start handshake measurement
            let mut pair = TestPair::from_config(&config);
            // Assert a successful handshake
            cg::cachegrind::start_instrumentation();
            assert!(pair.handshake().is_ok());
            cg::cachegrind::stop_instrumentation();
            return Ok(());
        }
        run_valgrind_test("test_rsa_handshake");
        Ok(())
    }
    // function to run specified test using valgrind
    fn run_valgrind_test(test_name: &str) {
        let exe_path = std::env::args().next().unwrap();
        let output_file = format!("cachegrind_{}.out", test_name);
        let valgrind_command = format!(
            "valgrind --tool=cachegrind --cachegrind-out-file={} {} {}",
            output_file, exe_path, test_name
        );
    
        println!("Running command: {}", valgrind_command);
        let output_command = format!("--cachegrind-out-file={}", &output_file);
        let status = Command::new("valgrind")
            .args(&["--tool=cachegrind", &output_command, &exe_path, test_name])
            .env_remove("VALGRIND") //ensures that the recursive call is made to the actual harness code block rather than back to this function
            .status()
            .expect("Failed to execute cargo test");
    
        if !status.success() {
            panic!("Valgrind failed");
        }
    
        let annotate_file = format!("perf_outputs/{}.annotated.txt", test_name);
        // this command annotates the raw output file and pipes it to the specified location
        let annotate_command = format!(
            "cg_annotate {} > {}",
            output_file, annotate_file
        );
    
        println!("Running command: {}", annotate_command);
    
        let annotate_status = Command::new("sh")
            .arg("-c")
            .arg(&annotate_command)
            .status()
            .expect("Failed to run cg_annotate");

        if !annotate_status.success() {
            panic!("cg_annotate failed");
        }
    
        let count = grep_for_instructions(&annotate_file).expect("Failed to get instruction count from file");
        //this is temporary code to showcase the future diff functionality, here the code regresses by 10% each time so this test will almost always fail in its current state
        let new_count = count + count / 10;
        let diff = new_count - count;
        assert!(diff <= self::COST, "Instruction count difference in {} exceeds the threshold, regression of {} instructions", test_name, diff);
    }

    use std::fs::File;
    use std::io::{self, BufRead};
    use std::path::Path;
    // parses the annotated file for the overall instruction count total
    fn grep_for_instructions(file_path: &str) -> Result<u64, io::Error> {
        let path = Path::new(file_path);
        let file = File::open(&path)?;
        let reader = io::BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if line.contains("PROGRAM TOTALS") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(instructions) = parts.get(0) {
                    if let Ok(instructions) = instructions.replace(",", "").parse::<u64>() {
                        return Ok(instructions);
                    }
                }
            }
        }

        Err(io::Error::new(io::ErrorKind::NotFound, "Failed to find instruction count in annotated file"))
    }
}
