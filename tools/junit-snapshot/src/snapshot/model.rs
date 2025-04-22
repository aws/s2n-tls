use crate::junit::{TestSuite, TestSuites};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Represents a snapshot of test results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Unique identifier for the snapshot
    pub id: String,
    
    /// When the snapshot was created
    pub timestamp: DateTime<Utc>,
    
    /// Name of the snapshot (optional)
    pub name: Option<String>,
    
    /// Description of the snapshot (optional)
    pub description: Option<String>,
    
    /// Source file that generated this snapshot
    pub source_file: PathBuf,
    
    /// Git commit hash at the time of snapshot creation (if available)
    pub git_commit: Option<String>,
    
    /// Git branch at the time of snapshot creation (if available)
    pub git_branch: Option<String>,
    
    /// Test results
    pub test_results: TestSuites,
}

impl Snapshot {
    /// Create a new snapshot from test results
    pub fn new(
        id: String,
        name: Option<String>,
        description: Option<String>,
        source_file: PathBuf,
        test_results: TestSuites,
    ) -> Self {
        Self {
            id,
            timestamp: Utc::now(),
            name,
            description,
            source_file,
            git_commit: None,
            git_branch: None,
            test_results,
        }
    }
    
    /// Set git information for the snapshot
    pub fn with_git_info(mut self, commit: Option<String>, branch: Option<String>) -> Self {
        self.git_commit = commit;
        self.git_branch = branch;
        self
    }
    
    /// Get summary statistics for the snapshot
    pub fn get_summary(&self) -> SnapshotSummary {
        let total_tests = self.test_results.tests;
        let total_failures = self.test_results.failures;
        let total_errors = self.test_results.errors;
        
        let total_skipped = self.test_results.test_suites.iter()
            .map(|suite| suite.skipped)
            .sum();
        
        let total_passed = total_tests - total_failures - total_errors - total_skipped;
        
        SnapshotSummary {
            id: self.id.clone(),
            timestamp: self.timestamp,
            total_tests,
            passed: total_passed,
            failed: total_failures,
            errors: total_errors,
            skipped: total_skipped,
        }
    }
}

/// Summary statistics for a snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotSummary {
    /// Snapshot ID
    pub id: String,
    
    /// When the snapshot was created
    pub timestamp: DateTime<Utc>,
    
    /// Total number of tests
    pub total_tests: u32,
    
    /// Number of passed tests
    pub passed: u32,
    
    /// Number of failed tests
    pub failed: u32,
    
    /// Number of tests with errors
    pub errors: u32,
    
    /// Number of skipped tests
    pub skipped: u32,
}

/// Collection of snapshots with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotCollection {
    /// Name of the collection
    pub name: String,
    
    /// When the collection was created
    pub created_at: DateTime<Utc>,
    
    /// When the collection was last updated
    pub updated_at: DateTime<Utc>,
    
    /// List of snapshot summaries
    pub snapshots: Vec<SnapshotSummary>,
}

impl SnapshotCollection {
    /// Create a new snapshot collection
    pub fn new(name: String) -> Self {
        let now = Utc::now();
        Self {
            name,
            created_at: now,
            updated_at: now,
            snapshots: Vec::new(),
        }
    }
    
    /// Add a snapshot summary to the collection
    pub fn add_snapshot(&mut self, summary: SnapshotSummary) {
        self.snapshots.push(summary);
        self.updated_at = Utc::now();
    }
    
    /// Remove a snapshot from the collection by ID
    pub fn remove_snapshot(&mut self, id: &str) -> bool {
        let len_before = self.snapshots.len();
        self.snapshots.retain(|s| s.id != id);
        let removed = self.snapshots.len() < len_before;
        
        if removed {
            self.updated_at = Utc::now();
        }
        
        removed
    }
}
