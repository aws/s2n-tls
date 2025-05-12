mod junit;
mod snapshot;

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use std::path::{PathBuf};
use colored::Colorize;

use crate::junit::{parse_junit_file};
use crate::snapshot::{
    generate_timestamp_id, get_git_branch, get_git_commit, Snapshot, SnapshotStorage,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new snapshot directory
    Init {
        /// Directory to initialize (defaults to current directory)
        #[arg(default_value = ".")]
        dir: PathBuf,
    },
    
    /// Capture a new snapshot from JUnit XML files
    Capture {
        /// JUnit XML file(s) to capture
        #[arg(required = true)]
        files: Vec<PathBuf>,
        
        /// Name for the snapshot
        #[arg(short, long)]
        name: Option<String>,
        
        /// Description for the snapshot
        #[arg(short, long)]
        description: Option<String>,
        
        /// Directory containing snapshots (defaults to current directory)
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    
    /// List available snapshots
    List {
        /// Directory containing snapshots (defaults to current directory)
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    
    /// Show details of a specific snapshot
    Show {
        /// Snapshot ID to show
        #[arg(required = true)]
        id: String,
        
        /// Directory containing snapshots (defaults to current directory)
        #[arg(default_value = ".")]
        dir: PathBuf,
    },
    
    /// Delete a snapshot
    Delete {
        /// Snapshot ID to delete
        #[arg(required = true)]
        id: String,
        
        /// Directory containing snapshots (defaults to current directory)
        #[arg(default_value = ".")]
        dir: PathBuf,
    },
    
    /// Compare a new JUnit file against a baseline snapshot
    Compare {
        /// JUnit XML file to compare
        #[arg(required = true)]
        file: PathBuf,
        
        /// Baseline snapshot ID to compare against
        #[arg(required = true)]
        baseline_id: String,
        
        /// Directory containing snapshots (defaults to current directory)
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        
        /// Only show differences (hide matching tests)
        #[arg(short, long)]
        diff_only: bool,
        
        /// Exit with non-zero status if differences are found
        #[arg(short, long)]
        fail_on_diff: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match &cli.command {
        Commands::Init { dir } => {
            println!("Initializing snapshot directory in {:?}", dir);
            let _storage = SnapshotStorage::init(dir)?;
            println!("Snapshot directory initialized successfully");
            Ok(())
        }
        
        Commands::Capture { files, name, description, dir } => {
            let mut storage = SnapshotStorage::new(dir)?;
            
            for file in files {
                println!("Capturing snapshot from {:?}", file);
                
                // Parse the JUnit XML file
                let test_results = parse_junit_file(file)?;
                
                // Create a new snapshot
                let id = generate_timestamp_id();
                let mut snapshot = Snapshot::new(
                    id.clone(),
                    name.clone(),
                    description.clone(),
                    file.clone(),
                    test_results,
                );
                
                // Add git information if available
                let git_commit = get_git_commit();
                let git_branch = get_git_branch();
                if git_commit.is_some() || git_branch.is_some() {
                    snapshot = snapshot.with_git_info(git_commit, git_branch);
                }
                
                // Save the snapshot
                storage.save_snapshot(&snapshot)?;
                
                println!("Snapshot created with ID: {}", id);
            }
            
            Ok(())
        }
        
        Commands::List { dir } => {
            let storage = SnapshotStorage::new(dir)?;
            let summaries = storage.get_snapshot_summaries();
            
            if summaries.is_empty() {
                println!("No snapshots found");
                return Ok(());
            }
            
            println!("Available snapshots:");
            for (i, summary) in summaries.iter().enumerate() {
                println!(
                    "{}: {} - {} (Tests: {}, Passed: {}, Failed: {}, Errors: {}, Skipped: {})",
                    i + 1,
                    summary.id,
                    summary.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    summary.total_tests,
                    summary.passed,
                    summary.failed,
                    summary.errors,
                    summary.skipped
                );
            }
            
            Ok(())
        }
        
        Commands::Show { id, dir } => {
            let storage = SnapshotStorage::new(dir)?;
            
            if !storage.snapshot_exists(id) {
                println!("Snapshot not found: {}", id);
                return Ok(());
            }
            
            let snapshot = storage.load_snapshot(id)?;
            
            println!("Snapshot ID: {}", snapshot.id);
            println!("Timestamp: {}", snapshot.timestamp.format("%Y-%m-%d %H:%M:%S"));
            
            if let Some(name) = &snapshot.name {
                println!("Name: {}", name);
            }
            
            if let Some(description) = &snapshot.description {
                println!("Description: {}", description);
            }
            
            println!("Source File: {:?}", snapshot.source_file);
            
            if let Some(git_commit) = &snapshot.git_commit {
                println!("Git Commit: {}", git_commit);
            }
            
            if let Some(git_branch) = &snapshot.git_branch {
                println!("Git Branch: {}", git_branch);
            }
            
            let summary = snapshot.get_summary();
            println!("\nTest Summary:");
            println!("  Total Tests: {}", summary.total_tests);
            println!("  Passed: {}", summary.passed);
            println!("  Failed: {}", summary.failed);
            println!("  Errors: {}", summary.errors);
            println!("  Skipped: {}", summary.skipped);
            
            println!("\nTest Suites:");
            for (i, suite) in snapshot.test_results.test_suites.iter().enumerate() {
                println!("\n  Suite {}: {}", i + 1, suite.name);
                println!("    Tests: {}", suite.tests);
                println!("    Failures: {}", suite.failures);
                println!("    Errors: {}", suite.errors);
                println!("    Skipped: {}", suite.skipped);
                println!("    Time: {:.3}s", suite.time);
            }
            
            Ok(())
        }
        
        Commands::Delete { id, dir } => {
            let mut storage = SnapshotStorage::new(dir)?;
            
            if !storage.snapshot_exists(id) {
                println!("Snapshot not found: {}", id);
                return Ok(());
            }
            
            storage.delete_snapshot(id)?;
            println!("Snapshot deleted: {}", id);
            
            Ok(())
        }
        
        Commands::Compare { file, baseline_id, dir, diff_only, fail_on_diff } => {
            let storage = SnapshotStorage::new(dir)?;
            
            // Check if baseline snapshot exists
            if !storage.snapshot_exists(baseline_id) {
                return Err(anyhow!("Baseline snapshot not found: {}", baseline_id));
            }
            
            // Load baseline snapshot
            let baseline = storage.load_snapshot(baseline_id)?;
            println!("Comparing {:?} against baseline snapshot: {}", file, baseline_id);
            
            // Parse the new JUnit file
            let current_results = parse_junit_file(file)?;
            
            // Compare the test results
            let mut has_differences = false;
            let mut total_tests = 0;
            let mut matching_tests = 0;
            let mut different_tests = 0;
            let mut new_tests = 0;
            let mut missing_tests = 0;
            
            // Create a map of test cases in the baseline for faster lookup
            let mut baseline_test_map = std::collections::HashMap::new();
            
            for suite in &baseline.test_results.test_suites {
                for test_case in &suite.test_cases {
                    let key = format!("{}::{}", suite.name, test_case.name);
                    baseline_test_map.insert(key, (suite.name.clone(), test_case));
                }
            }
            
            // Compare each test suite and test case
            for current_suite in &current_results.test_suites {
                println!("\nTest Suite: {}", current_suite.name.bold());
                
                for current_test in &current_suite.test_cases {
                    total_tests += 1;
                    let test_key = format!("{}::{}", current_suite.name, current_test.name);
                    
                    // Determine test status
                    let current_status = if current_test.failure.is_some() {
                        "FAIL"
                    } else if current_test.error.is_some() {
                        "ERROR"
                    } else if current_test.skipped.is_some() {
                        "SKIP"
                    } else {
                        "PASS"
                    };
                    
                    if let Some((_, baseline_test)) = baseline_test_map.get(&test_key) {
                        // Test exists in baseline, compare status
                        let baseline_status = if baseline_test.failure.is_some() {
                            "FAIL"
                        } else if baseline_test.error.is_some() {
                            "ERROR"
                        } else if baseline_test.skipped.is_some() {
                            "SKIP"
                        } else {
                            "PASS"
                        };
                        
                        if current_status == baseline_status {
                            matching_tests += 1;
                            if !diff_only {
                                println!("  {} {}", "✓".green(), current_test.name);
                            }
                        } else {
                            different_tests += 1;
                            has_differences = true;
                            println!("  {} {} (was: {}, now: {})", 
                                "✗".red(), 
                                current_test.name,
                                baseline_status,
                                current_status
                            );
                            
                            // Show more details about the difference
                            if current_test.failure.is_some() && baseline_test.failure.is_some() {
                                println!("    Failure message changed:");
                                println!("      Baseline: {}", baseline_test.failure.as_ref().unwrap().message);
                                println!("      Current: {}", current_test.failure.as_ref().unwrap().message);
                            } else if current_test.error.is_some() && baseline_test.error.is_some() {
                                println!("    Error message changed:");
                                println!("      Baseline: {}", baseline_test.error.as_ref().unwrap().message);
                                println!("      Current: {}", current_test.error.as_ref().unwrap().message);
                            }
                        }
                    } else {
                        // Test doesn't exist in baseline
                        new_tests += 1;
                        has_differences = true;
                        println!("  {} {} (new test)", "+".blue(), current_test.name);
                    }
                }
            }
            
            // Check for tests in baseline that are missing in current results
            for (key, (_, _)) in &baseline_test_map {
                let parts: Vec<&str> = key.split("::").collect();
                if parts.len() == 2 {
                    let suite_name = parts[0];
                    let test_name = parts[1];
                    
                    // Check if this test exists in current results
                    let exists = current_results.test_suites.iter().any(|suite| {
                        suite.name == suite_name && 
                        suite.test_cases.iter().any(|tc| tc.name == test_name)
                    });
                    
                    if !exists {
                        missing_tests += 1;
                        has_differences = true;
                        println!("  {} {} (missing test from suite {})", "-".yellow(), test_name, suite_name);
                    }
                }
            }
            
            // Print summary
            println!("\nComparison Summary:");
            println!("  Total tests: {}", total_tests);
            println!("  Matching tests: {}", matching_tests);
            println!("  Different tests: {}", different_tests);
            println!("  New tests: {}", new_tests);
            println!("  Missing tests: {}", missing_tests);
            
            if has_differences {
                println!("\n{}", "Differences found!".yellow());
                if *fail_on_diff {
                    return Err(anyhow!("Test results differ from baseline"));
                }
            } else {
                println!("\n{}", "All tests match the baseline.".green());
            }
            
            Ok(())
        }
    }
}
