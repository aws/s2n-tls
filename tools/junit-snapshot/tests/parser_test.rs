use junit_snapshot::{parse_junit_file, validate_test_suites};
use std::path::Path;

#[test]
fn test_parse_multiple_test_suites() {
    let path = Path::new("tests/integrationv2_happy_path.xml");
    let test_suites = parse_junit_file(path).expect("Failed to parse integrationv2_happy_path.xml");
    
    assert_eq!(test_suites.test_suites.len(), 1);
    assert_eq!(test_suites.tests, 8840);
    assert_eq!(test_suites.failures, 0);
    assert_eq!(test_suites.errors, 0);
    
    // Validate first test suite
    let first_suite = &test_suites.test_suites[0];
    assert_eq!(first_suite.name, "pytest");
    assert_eq!(first_suite.tests, 8840);
    assert_eq!(first_suite.failures, 0);
    assert_eq!(first_suite.errors, 0);
    assert_eq!(first_suite.skipped, 0);
    
    // Validate test cases
    assert!(first_suite.test_cases.len() > 0);
    
    // Validate a specific test case
    let test_case = &first_suite.test_cases[0];
    assert_eq!(test_case.name, "test_s2n_server_happy_path[RSA_1024_SHA256-TLS1.3-X25519-S2N-TLS_CHACHA20_POLY1305_SHA256]");
    
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
