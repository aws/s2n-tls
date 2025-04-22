use junit_snapshot::junit::parser::parse_junit_file;
use std::path::Path;

#[test]
fn test_parse_sni_match_xml() {
    let file_path = Path::new("tests/integrationv2_sni_match.xml");
    let result = parse_junit_file(file_path);
    
    // Verify that parsing succeeds
    assert!(result.is_ok(), "Failed to parse integrationv2_sni_match.xml: {:?}", result.err());
    
    let test_suites = result.unwrap();
    
    // Verify basic structure
    assert_eq!(test_suites.test_suites.len(), 1, "Expected 1 test suite");
    
    let suite = &test_suites.test_suites[0];
    assert_eq!(suite.name, "pytest", "Expected suite name to be 'pytest'");
    assert_eq!(suite.tests, 88, "Expected 88 tests");
    assert_eq!(suite.failures, 0, "Expected 0 failures");
    assert_eq!(suite.errors, 0, "Expected 0 errors");
    assert_eq!(suite.skipped, 0, "Expected 0 skipped tests");
    
    // Verify test cases
    assert_eq!(suite.test_cases.len(), 88, "Expected 88 test cases");
    
    // Check a specific test case
    let first_test = &suite.test_cases[0];
    assert_eq!(first_test.name, "test_sni_match[cert_test_case1-TLS1.3-S2N-OpenSSL]");
    assert_eq!(first_test.classname, "test_sni_match");
    assert_eq!(first_test.status, junit_snapshot::junit::model::TestStatus::Success);
}
