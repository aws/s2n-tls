use crate::junit::model::{TestSuite, TestSuites};
use anyhow::{Context, Result};
use quick_xml::de::from_str;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParserError {
    #[error("Failed to read file: {0}")]
    FileReadError(String),
    
    #[error("Failed to parse XML: {0}")]
    XmlParseError(String),
    
    #[error("Invalid JUnit XML format: {0}")]
    InvalidFormat(String),
}

/// Parse a JUnit XML file into our data model
pub fn parse_junit_file<P: AsRef<Path>>(path: P) -> Result<TestSuites> {
    let path_str = path.as_ref().to_string_lossy().to_string();
    
    // Read the file content
    let content = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read JUnit XML file: {}", path_str))
        .map_err(|e| ParserError::FileReadError(e.to_string()))?;
    
    parse_junit_xml(&content)
        .with_context(|| format!("Failed to parse JUnit XML file: {}", path_str))
}

/// Parse JUnit XML content into our data model
pub fn parse_junit_xml(content: &str) -> Result<TestSuites> {
    // Try to parse as TestSuites (multiple test suites)
    let result: Result<TestSuites, _> = from_str(content);
    
    match result {
        Ok(mut test_suites) => {
            // Process each test case to determine its status
            for suite in &mut test_suites.test_suites {
                for test_case in &mut suite.test_cases {
                    test_case.determine_status();
                }
            }
            Ok(test_suites)
        }
        Err(e) => {
            // If parsing as TestSuites fails, try parsing as a single TestSuite
            let result: Result<TestSuite, _> = from_str(content);
            match result {
                Ok(mut test_suite) => {
                    // Process each test case to determine its status
                    for test_case in &mut test_suite.test_cases {
                        test_case.determine_status();
                    }
                    
                    // Create a TestSuites wrapper with a single TestSuite
                    Ok(TestSuites {
                        name: test_suite.name.clone(),
                        tests: test_suite.tests,
                        failures: test_suite.failures,
                        errors: test_suite.errors,
                        time: test_suite.time,
                        test_suites: vec![test_suite],
                    })
                }
                Err(_) => {
                    // Both parsing attempts failed
                    Err(ParserError::XmlParseError(e.to_string()).into())
                }
            }
        }
    }
}

/// Validate that the parsed TestSuites object is consistent
pub fn validate_test_suites(test_suites: &TestSuites) -> Result<()> {
    // Check if the total number of tests matches the sum of tests in each suite
    let total_tests_in_suites: u32 = test_suites.test_suites.iter()
        .map(|suite| suite.tests)
        .sum();
    
    if test_suites.tests != total_tests_in_suites {
        return Err(ParserError::InvalidFormat(format!(
            "Total test count mismatch: {} vs {}",
            test_suites.tests, total_tests_in_suites
        )).into());
    }
    
    // Validate each test suite
    for suite in &test_suites.test_suites {
        validate_test_suite(suite)?;
    }
    
    Ok(())
}

/// Validate that a TestSuite object is consistent
fn validate_test_suite(test_suite: &TestSuite) -> Result<()> {
    // Check if the number of test cases matches the reported test count
    if test_suite.tests as usize != test_suite.test_cases.len() {
        return Err(ParserError::InvalidFormat(format!(
            "Test suite '{}' has {} test cases but reports {} tests",
            test_suite.name, test_suite.test_cases.len(), test_suite.tests
        )).into());
    }
    
    // Count failures, errors, and skipped tests
    let mut failures = 0;
    let mut errors = 0;
    let mut skipped = 0;
    
    for test_case in &test_suite.test_cases {
        if test_case.failure.is_some() {
            failures += 1;
        }
        if test_case.error.is_some() {
            errors += 1;
        }
        if test_case.skipped.is_some() {
            skipped += 1;
        }
    }
    
    // Check if the counts match
    if test_suite.failures != failures {
        return Err(ParserError::InvalidFormat(format!(
            "Test suite '{}' reports {} failures but has {} failed test cases",
            test_suite.name, test_suite.failures, failures
        )).into());
    }
    
    if test_suite.errors != errors {
        return Err(ParserError::InvalidFormat(format!(
            "Test suite '{}' reports {} errors but has {} error test cases",
            test_suite.name, test_suite.errors, errors
        )).into());
    }
    
    if test_suite.skipped != skipped {
        return Err(ParserError::InvalidFormat(format!(
            "Test suite '{}' reports {} skipped but has {} skipped test cases",
            test_suite.name, test_suite.skipped, skipped
        )).into());
    }
    
    Ok(())
}
