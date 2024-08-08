// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod git {
    use std::process::Command;

    pub fn get_current_commit_hash() -> String {
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("Failed to get commit hash");
        assert!(output.status.success());

        String::from_utf8(output.stdout)
            .expect("Invalid UTF-8 in commit hash")
            .trim()
            .to_string()
    }

    /// Returns true if `commit1` is older than `commit2`
    pub fn is_older_commit(commit1: &str, commit2: &str) -> bool {
        let status = Command::new("git")
            .args(["merge-base", "--is-ancestor", commit1, commit2])
            .status()
            .expect("Failed to execute git merge-base");
        status.success()
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
    use s2n_tls::{
        config::Builder,
        security,
        testing::{CertKeyPair, InsecureAcceptAllCertificatesHandler},
    };
    type Error = s2n_tls::error::Error;
    use super::*;
    use crabgrind as cg;
    use s2n_tls::testing::TestPair;
    use std::{
        env,
        fs::{create_dir_all, write},
        io::{self, BufRead},
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

    #[derive(Debug)]
    enum RegressionTestMode {
        Default,
        Valgrind,
        Diff,
    }

    impl RegressionTestMode {
        fn from_env() -> Self {
            match env::var("PERF_MODE").as_deref() {
                Ok("valgrind") => RegressionTestMode::Valgrind,
                Ok("diff") => RegressionTestMode::Diff,
                _ => RegressionTestMode::Default,
            }
        }
    }

    fn valgrind_test<F>(test_name: &str, test_body: F) -> Result<(), s2n_tls::error::Error>
    where
        F: FnOnce(&InstrumentationControl) -> Result<(), s2n_tls::error::Error>,
    {
        match RegressionTestMode::from_env() {
            RegressionTestMode::Valgrind => {
                let raw_profile = RawProfile::new(test_name);
                AnnotatedProfile::new(&raw_profile);
            }
            RegressionTestMode::Diff => {
                let (prev_profile, curr_profile) = RawProfile::query(test_name);
                DiffProfile::new(&prev_profile, &curr_profile).assert_performance();
            }
            RegressionTestMode::Default => {
                let ctrl = InstrumentationControl;
                test_body(&ctrl)?
            }
        };
        Ok(())
    }

    struct RawProfile {
        test_name: String,
        commit_hash: String,
    }

    impl RawProfile {
        fn new(test_name: &str) -> Self {
            let commit_hash = git::get_current_commit_hash();
            create_dir_all(format!("target/{commit_hash}")).unwrap();

            let raw_profile = Self {
                test_name: test_name.to_owned(),
                commit_hash,
            };

            let mut command = Command::new("valgrind");
            command
                .args([
                    // use cachegrind to get instruction count
                    "--tool=cachegrind",
                    // write output to output file
                    &format!("--cachegrind-out-file={}", raw_profile.path()),
                    // the "cargo test" executable
                    &std::env::args().next().unwrap(),
                    test_name,
                ])
                // remove environment variable to prevent recursive loop
                .env_remove("PERF_MODE");
            assert_command_success(command.output().unwrap());

            raw_profile
        }

        fn path(&self) -> String {
            format!("target/{}/{}.raw", self.commit_hash, self.test_name)
        }

        /// Return the raw profiles for `test_name` in "git" order. `tuple.0` is older than `tuple.1`
        ///
        /// This method will panic if there are not two profiles.
        fn query(test_name: &str) -> (RawProfile, RawProfile) {
            let pattern = format!("target/**/*{}.raw", test_name);
            let raw_files: Vec<String> = glob::glob(&pattern)
                .expect("Failed to read glob pattern")
                .filter_map(Result::ok)
                .map(|path| path.to_string_lossy().into_owned())
                .collect();
            assert_eq!(raw_files.len(), 2);

            let profile1 = RawProfile {
                test_name: test_name.to_string(),
                commit_hash: git::extract_commit_hash(&raw_files[0]),
            };

            let profile2 = RawProfile {
                test_name: test_name.to_string(),
                commit_hash: git::extract_commit_hash(&raw_files[1]),
            };

            if git::is_older_commit(&profile1.commit_hash, &profile2.commit_hash) {
                (profile1, profile2)
            } else if git::is_older_commit(&profile2.commit_hash, &profile1.commit_hash) {
                (profile2, profile1)
            } else {
                panic!("The commits are not in the same log");
            }
        }
    }

    struct AnnotatedProfile {
        test_name: String,
        commit_hash: String,
    }

    impl AnnotatedProfile {
        fn new(raw_profile: &RawProfile) -> Self {
            let annotated = Self {
                test_name: raw_profile.test_name.clone(),
                commit_hash: raw_profile.commit_hash.clone(),
            };

            // annotate raw profile
            let annotate_output = Command::new("cg_annotate")
                .arg(raw_profile.path())
                .output()
                .expect("Failed to run cg_annotate");
            assert_command_success(annotate_output.clone());

            // write annotated profile to disk
            let annotate_content = String::from_utf8(annotate_output.stdout)
                .expect("Invalid UTF-8 in cg_annotate output");
            write(annotated.path(), annotate_content).expect("Failed to write to file");

            annotated
        }

        fn path(&self) -> String {
            format!("target/{}/{}.annotated", self.commit_hash, self.test_name)
        }
    }

    struct DiffProfile {
        test_name: String,
    }
    impl DiffProfile {
        fn new(prev_profile: &RawProfile, curr_profile: &RawProfile) -> Self {
            let diff_profile = Self {
                test_name: curr_profile.test_name.clone(),
            };

            // diff the raw profile
            let diff_output = Command::new("cg_annotate")
                .args(["--diff", &prev_profile.path(), &curr_profile.path()])
                .output()
                .expect("Failed to run cg_annotate --diff");
            assert_command_success(diff_output.clone());

            // write the diff to disk
            let diff_content = String::from_utf8(diff_output.stdout)
                .expect("Invalid UTF-8 in cg_annotate --diff output");
            write(diff_profile.path(), diff_content).expect("Failed to write to file");

            diff_profile
        }

        fn path(&self) -> String {
            format!("target/diff/{}.diff", self.test_name)
        }

        fn assert_performance(&self) {
            let diff_content = std::fs::read_to_string(self.path()).unwrap();

            let diff = find_instruction_count(&diff_content)
                .expect("Failed to parse cg_annotate --diff output");
            assert!(
                diff <= MAX_DIFF,
                "Instruction count difference exceeds the threshold, regression of {} instructions. 
                Check the annotated output logs in target/diff/{}.diff for debug information",
                diff, self.test_name
            );
        }
    }

    // Pulls the instruction count as an integer from the annotated output file.
    fn find_instruction_count(output: &str) -> Result<i64, io::Error> {
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

    // Asserts that a command executed successfully, panic with stdout/stderr if it fails
    fn assert_command_success(output: Output) {
        if !output.status.success() {
            let stdout = std::str::from_utf8(&output.stdout).unwrap_or("Failed to read stdout");
            let stderr = std::str::from_utf8(&output.stderr).unwrap_or("Failed to read stderr");
            panic!(
                "Command failed with status: {}\nstdout: {}\nstderr: {}",
                output.status, stdout, stderr
            );
        }
    }

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
}
