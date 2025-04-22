use junit_snapshot::{parse_junit_file, validate_test_suites};
use std::path::Path;

#[test]
fn test_parse_multiple_test_suites() {
    let path = Path::new("tests/sample.xml");
    let test_suites = parse_junit_file(path).expect("Failed to parse sample.xml");
    
    assert_eq!(test_suites.test_suites.len(), 2);
    assert_eq!(test_suites.tests, 7);
    assert_eq!(test_suites.failures, 1);
    assert_eq!(test_suites.errors, 1);
    
    // Validate first test suite
    let first_suite = &test_suites.test_suites[0];
    assert_eq!(first_suite.name, "s2n_handshake_test");
    assert_eq!(first_suite.tests, 4);
    assert_eq!(first_suite.failures, 1);
    assert_eq!(first_suite.errors, 0);
    assert_eq!(first_suite.skipped, 2);
    
    // Validate second test suite
    let second_suite = &test_suites.test_suites[1];
    assert_eq!(second_suite.name, "s2n_crypto_test");
    assert_eq!(second_suite.tests, 3);
    assert_eq!(second_suite.failures, 0);
    assert_eq!(second_suite.errors, 1);
    assert_eq!(second_suite.skipped, 0);
    
    // Validate test cases
    assert_eq!(first_suite.test_cases.len(), 4);
    assert_eq!(second_suite.test_cases.len(), 3);
    
    // Validate a specific test case
    let failed_test = &first_suite.test_cases[1];
    assert_eq!(failed_test.name, "test_failed_handshake");
    assert!(failed_test.failure.is_some());
    
    // Validate the test suites structure
    validate_test_suites(&test_suites).expect("Test suites validation failed");
}

#[test]
fn test_parse_single_test_suite() {
    let path = Path::new("tests/single_suite.xml");
    let test_suites = parse_junit_file(path).expect("Failed to parse single_suite.xml");
    
    // Even though the XML contains a single testsuite, our parser should wrap it in TestSuites
    assert_eq!(test_suites.test_suites.len(), 1);
    
    let suite = &test_suites.test_suites[0];
    assert_eq!(suite.name, "s2n_single_test");
    assert_eq!(suite.tests, 3);
    assert_eq!(suite.failures, 1);
    assert_eq!(suite.errors, 0);
    assert_eq!(suite.skipped, 0);
    
    // Validate test cases
    assert_eq!(suite.test_cases.len(), 3);
    
    // Validate the test suites structure
    validate_test_suites(&test_suites).expect("Test suites validation failed");
}
