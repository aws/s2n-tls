mod junit;

use anyhow::Result;
use std::env;
use std::path::Path;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: {} <junit-xml-file>", args[0]);
        return Ok(());
    }
    
    let file_path = Path::new(&args[1]);
    
    // Parse the JUnit XML file
    let test_suites = junit::parse_junit_file(file_path)?;
    
    // Validate the parsed data
    junit::validate_test_suites(&test_suites)?;
    
    // Print summary information
    println!("Test Suites: {}", test_suites.test_suites.len());
    println!("Total Tests: {}", test_suites.tests);
    println!("Failures: {}", test_suites.failures);
    println!("Errors: {}", test_suites.errors);
    
    // Print details for each test suite
    for (i, suite) in test_suites.test_suites.iter().enumerate() {
        println!("\nTest Suite {}: {}", i + 1, suite.name);
        println!("  Tests: {}", suite.tests);
        println!("  Failures: {}", suite.failures);
        println!("  Errors: {}", suite.errors);
        println!("  Skipped: {}", suite.skipped);
        println!("  Time: {:.3}s", suite.time);
        
        // Print details for each test case
        for (j, test_case) in suite.test_cases.iter().enumerate() {
            let status = if test_case.failure.is_some() {
                "FAIL"
            } else if test_case.error.is_some() {
                "ERROR"
            } else if test_case.skipped.is_some() {
                "SKIP"
            } else {
                "PASS"
            };
            
            println!("    {}: {} - {} ({:.3}s)", j + 1, status, test_case.name, test_case.time);
            
            // Print failure details if present
            if let Some(failure) = &test_case.failure {
                println!("      Failure: {} - {}", failure.failure_type, failure.message);
                if !failure.text.is_empty() {
                    println!("      Details: {}", failure.text);
                }
            }
            
            // Print error details if present
            if let Some(error) = &test_case.error {
                println!("      Error: {} - {}", error.error_type, error.message);
                if !error.text.is_empty() {
                    println!("      Details: {}", error.text);
                }
            }
        }
    }
    
    Ok(())
}
