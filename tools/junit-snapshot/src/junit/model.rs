use serde::{Deserialize, Serialize};
use std::fmt;

/// Status of a test case
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TestStatus {
    Success,
    Failure,
    Error,
    Skipped,
}

impl Default for TestStatus {
    fn default() -> Self {
        TestStatus::Success
    }
}

impl fmt::Display for TestStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TestStatus::Success => write!(f, "Success"),
            TestStatus::Failure => write!(f, "Failure"),
            TestStatus::Error => write!(f, "Error"),
            TestStatus::Skipped => write!(f, "Skipped"),
        }
    }
}

/// Represents an individual test case from JUnit XML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    #[serde(rename = "@name")]
    pub name: String,
    
    #[serde(rename = "@classname")]
    pub classname: String,
    
    #[serde(rename = "@time")]
    pub time: f64,
    
    #[serde(skip_serializing, skip_deserializing)]
    #[serde(default)]
    pub status: TestStatus,
    
    pub failure: Option<Failure>,
    pub error: Option<Error>,
    pub skipped: Option<Skipped>,
    
    #[serde(rename = "system-out")]
    pub system_out: Option<String>,
    
    #[serde(rename = "system-err")]
    pub system_err: Option<String>,
}

impl TestCase {
    /// Determine the status of the test case based on its fields
    pub fn determine_status(&mut self) {
        self.status = if self.failure.is_some() {
            TestStatus::Failure
        } else if self.error.is_some() {
            TestStatus::Error
        } else if self.skipped.is_some() {
            TestStatus::Skipped
        } else {
            TestStatus::Success
        };
    }
}

/// Represents a failure in a test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Failure {
    #[serde(rename = "@message", default)]
    pub message: String,
    
    #[serde(rename = "@type", default)]
    pub failure_type: String,
    
    #[serde(rename = "$text", default)]
    pub text: String,
}

/// Represents an error in a test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Error {
    #[serde(rename = "@message", default)]
    pub message: String,
    
    #[serde(rename = "@type", default)]
    pub error_type: String,
    
    #[serde(rename = "$text", default)]
    pub text: String,
}

/// Represents a skipped test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skipped {
    #[serde(rename = "@message", default)]
    pub message: String,
    
    #[serde(rename = "$text", default)]
    pub text: String,
}

/// Represents a test suite from JUnit XML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSuite {
    #[serde(rename = "@name")]
    pub name: String,
    
    #[serde(rename = "@tests")]
    pub tests: u32,
    
    #[serde(rename = "@failures")]
    pub failures: u32,
    
    #[serde(rename = "@errors")]
    pub errors: u32,
    
    #[serde(rename = "@skipped", default)]
    pub skipped: u32,
    
    #[serde(rename = "@time")]
    pub time: f64,
    
    #[serde(rename = "@timestamp")]
    pub timestamp: String,
    
    #[serde(rename = "testcase")]
    pub test_cases: Vec<TestCase>,
}

/// Root element of JUnit XML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSuites {
    #[serde(rename = "@name", default)]
    pub name: String,
    
    #[serde(rename = "@tests")]
    pub tests: u32,
    
    #[serde(rename = "@failures")]
    pub failures: u32,
    
    #[serde(rename = "@errors")]
    pub errors: u32,
    
    #[serde(rename = "@time", default)]
    pub time: f64,
    
    #[serde(rename = "testsuite")]
    pub test_suites: Vec<TestSuite>,
}
