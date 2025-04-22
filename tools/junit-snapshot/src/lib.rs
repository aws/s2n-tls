pub mod junit;

// Re-export the main functionality
pub use junit::{
    model::{TestCase, TestStatus, TestSuite, TestSuites},
    parser::{parse_junit_file, parse_junit_xml, validate_test_suites},
};
