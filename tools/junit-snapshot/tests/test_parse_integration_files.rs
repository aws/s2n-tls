use junit_snapshot::junit::parser::parse_junit_file;
use std::path::Path;

// Helper function to test parsing of a JUnit XML file
fn test_parse_file(filename: &str) {
    let file_path_str = format!("tests/{}", filename);
    let file_path = Path::new(&file_path_str);
    let result = parse_junit_file(file_path);
    
    assert!(result.is_ok(), "Failed to parse {}: {:?}", filename, result.err());
    
    let test_suites = result.unwrap();
    
    // Basic validation
    assert!(!test_suites.test_suites.is_empty(), "No test suites found in {}", filename);
    
    // Verify the first test suite has test cases
    let first_suite = &test_suites.test_suites[0];
    assert!(!first_suite.test_cases.is_empty(), "No test cases found in first suite of {}", filename);
    
    println!("Successfully parsed {} with {} test suites and {} test cases in first suite", 
             filename, test_suites.test_suites.len(), first_suite.test_cases.len());
}

#[test]
fn test_parse_buffered_send() {
    test_parse_file("integrationv2_buffered_send.xml");
}

#[test]
fn test_parse_client_authentication() {
    test_parse_file("integrationv2_client_authentication.xml");
}

#[test]
fn test_parse_cross_compatibility() {
    test_parse_file("integrationv2_cross_compatibility.xml");
}

#[test]
fn test_parse_dynamic_record_sizes() {
    test_parse_file("integrationv2_dynamic_record_sizes.xml");
}

#[test]
fn test_parse_early_data() {
    test_parse_file("integrationv2_early_data.xml");
}

#[test]
fn test_parse_external_psk() {
    test_parse_file("integrationv2_external_psk.xml");
}

#[test]
fn test_parse_fragmentation() {
    test_parse_file("integrationv2_fragmentation.xml");
}

#[test]
fn test_parse_hello_retry_requests() {
    test_parse_file("integrationv2_hello_retry_requests.xml");
}

#[test]
fn test_parse_key_update() {
    test_parse_file("integrationv2_key_update.xml");
}

#[test]
fn test_parse_npn() {
    test_parse_file("integrationv2_npn.xml");
}

#[test]
fn test_parse_ocsp() {
    test_parse_file("integrationv2_ocsp.xml");
}

#[test]
fn test_parse_pq_handshake() {
    test_parse_file("integrationv2_pq_handshake.xml");
}

#[test]
fn test_parse_record_padding() {
    test_parse_file("integrationv2_record_padding.xml");
}

#[test]
fn test_parse_renegotiate_apache() {
    test_parse_file("integrationv2_renegotiate_apache.xml");
}

#[test]
fn test_parse_renegotiate() {
    test_parse_file("integrationv2_renegotiate.xml");
}

#[test]
fn test_parse_serialization() {
    test_parse_file("integrationv2_serialization.xml");
}

#[test]
fn test_parse_session_resumption() {
    test_parse_file("integrationv2_session_resumption.xml");
}

#[test]
fn test_parse_signature_algorithms() {
    test_parse_file("integrationv2_signature_algorithms.xml");
}

#[test]
fn test_parse_sslv2_client_hello() {
    test_parse_file("integrationv2_sslv2_client_hello.xml");
}

#[test]
fn test_parse_sslyze() {
    test_parse_file("integrationv2_sslyze.xml");
}

#[test]
fn test_parse_version_negotiation() {
    test_parse_file("integrationv2_version_negotiation.xml");
}
