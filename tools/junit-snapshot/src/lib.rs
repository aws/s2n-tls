pub mod junit;
pub mod snapshot;

// Re-export the main functionality
pub use junit::{
    model::{TestCase, TestStatus, TestSuite, TestSuites},
    parser::{parse_junit_file, parse_junit_xml, validate_test_suites},
};

pub use snapshot::{
    model::{Snapshot, SnapshotCollection, SnapshotSummary},
    storage::SnapshotStorage,
    utils::{generate_snapshot_id, generate_timestamp_id, get_git_branch, get_git_commit},
};
