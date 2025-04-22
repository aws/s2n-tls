pub mod model;
pub mod parser;

pub use model::{TestCase, TestStatus, TestSuite, TestSuites};
pub use parser::{parse_junit_file, parse_junit_xml, validate_test_suites};
