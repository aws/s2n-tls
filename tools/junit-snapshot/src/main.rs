mod junit;
mod snapshot;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::{PathBuf};

use crate::junit::parse_junit_file;
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
    },
    
    /// List available snapshots
    List {
        /// Directory containing snapshots (defaults to current directory)
        #[arg(default_value = ".")]
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
        
        Commands::Capture { files, name, description } => {
            let mut storage = SnapshotStorage::new(".")?;
            
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
    }
}
