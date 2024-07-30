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

    fn is_running_under_valgrind() -> bool {
        env::var("ENABLE_VALGRIND").is_ok()
    }

    fn is_diff_mode() -> bool {
        env::var("DIFF_MODE").is_ok()
    }

    fn valgrind_test<F>(test_name: &str, test_body: F) -> Result<(), s2n_tls::error::Error>
    where
        F: FnOnce(&InstrumentationControl) -> Result<(), s2n_tls::error::Error>,
    {
        if !is_running_under_valgrind() {
            if is_diff_mode() {
                run_diff_test(test_name);
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
        let commit_hash = get_current_commit_hash();
        let output_file = create_output_file_path(test_name, &commit_hash);
        let command = build_valgrind_command(&exe_path, test_name, &output_file);

        println!("Running command: {:?}", command);
        execute_command(command);

        let annotate_output = run_cg_annotate(&output_file);
        save_annotate_output(&annotate_output, &commit_hash, test_name);

        let count = find_instruction_count(&annotate_output)
            .expect("Failed to get instruction count from file");

        println!("Instruction count for {}: {}", test_name, count);
    }

    fn get_current_commit_hash() -> String {
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

    fn create_output_file_path(test_name: &str, commit_hash: &str) -> String {
        create_dir_all(Path::new("target/cg_artifacts")).unwrap();
        format!("target/cg_artifacts/cachegrind_{test_name}_{commit_hash}.out")
    }

    fn build_valgrind_command(exe_path: &str, test_name: &str, output_file: &str) -> Command {
        let output_command = format!("--cachegrind-out-file={}", output_file);
        let mut command = Command::new("valgrind");
        command
            .args(["--tool=cachegrind", &output_command, exe_path, test_name])
            .env_remove("ENABLE_VALGRIND");
        command
    }

    fn execute_command(mut command: Command) {
        let status = command.status().expect("Failed to execute valgrind");
        if !status.success() {
            panic!("Valgrind failed");
        }
    }

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

    fn save_annotate_output(output: &std::process::Output, commit_hash: &str, test_name: &str) {
        let directory = "target/perf_outputs";
        create_dir_all(Path::new(&directory)).unwrap();
        let annotate_file = format!("target/perf_outputs/{test_name}_{commit_hash}.annotated.txt");
        let mut file = File::create(annotate_file).expect("Failed to create annotation file");
        file.write_all(&output.stdout)
            .expect("Failed to write annotation file");
    }

    /// Function to run the diff test using valgrind, only called when diff mode is set
    fn run_diff_test(test_name: &str) {
        let (prev_file, curr_file) = find_and_validate_diff_files(test_name);
        let diff_output = run_cg_annotate_diff(&prev_file, &curr_file);
        save_diff_output(&diff_output, test_name);

        let diff = find_instruction_count(&diff_output)
            .expect("Failed to parse cg_annotate --diff output");

        assert_diff_within_threshold(diff, test_name);
    }

    fn find_and_validate_diff_files(test_name: &str) -> (String, String) {
        let annotated_files = find_annotated_files(test_name);
        if annotated_files.len() != 2 {
            panic!(
                "Expected exactly 2 annotated files for {}, found {}",
                test_name,
                annotated_files.len()
            );
        }

        let file1 = &annotated_files[0];
        let file2 = &annotated_files[1];

        if !is_commit_in_log(file1) || !is_commit_in_log(file2) {
            panic!(
                "One or both commit hashes are not in the git log: {} or {}",
                extract_commit_hash(file1),
                extract_commit_hash(file2)
            );
        }

        let (old_file, new_file) = if is_older_commit(file1, file2) {
            (file1.clone(), file2.clone())
        } else if is_older_commit(file2, file1) {
            (file2.clone(), file1.clone())
        } else {
            panic!(
                "Cannot determine the older commit between {} and {}",
                file1, file2
            );
        };

        (old_file, new_file)
    }

    fn find_annotated_files(test_name: &str) -> Vec<String> {
        let pattern = format!("target/perf_outputs/{}_*.annotated.txt", test_name);
        glob::glob(&pattern)
            .expect("Failed to read glob pattern")
            .filter_map(Result::ok)
            .map(|path| path.to_string_lossy().into_owned())
            .collect()
    }

    fn is_commit_in_log(file: &str) -> bool {
        let commit = extract_commit_hash(file);
        let output = Command::new("git")
            .args(["log", "--pretty=format:%H"])
            .output()
            .expect("Failed to execute git log");
        let log = String::from_utf8(output.stdout).expect("Invalid UTF-8 in git log output");
        log.lines().any(|line| line == commit)
    }

    fn is_older_commit(file1: &str, file2: &str) -> bool {
        let commit1 = extract_commit_hash(file1);
        let commit2 = extract_commit_hash(file2);
        let output = Command::new("git")
            .args(["merge-base", "--is-ancestor", &commit1, &commit2])
            .status()
            .expect("Failed to execute git merge-base");
        output.success()
    }

    fn extract_commit_hash(file: &str) -> String {
        let parts: Vec<&str> = file.split('_').collect();
        parts[parts.len() - 1]
            .replace(".annotated.txt", "")
            .to_string()
    }

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

    fn save_diff_output(output: &std::process::Output, test_name: &str) {
        create_dir_all(Path::new("target/perf_outputs/diff")).unwrap();
        let diff_file = format!("target/perf_outputs/diff/{test_name}_diff.annotated.txt");
        let mut file = File::create(diff_file).expect("failed to create diff annotation file");
        file.write_all(&output.stdout)
            .expect("Failed to write diff annotation file");
    }

    fn assert_diff_within_threshold(diff: i64, test_name: &str) {
        assert!(
            diff <= MAX_DIFF,
            "Instruction count difference in {} exceeds the threshold, regression of {} instructions. 
            Check the annotated output logs in {}_diff.annotated.txt for debug information",
            test_name, diff, test_name
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
