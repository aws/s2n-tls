use std::fs;
use std::process::Command;
use tempfile::tempdir;
use assert_cmd::prelude::*;
use predicates::prelude::*;

#[test]
fn test_compare_identical_files() {
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();
    
    // Initialize snapshot directory
    Command::cargo_bin("junit-snapshot")
        .unwrap()
        .arg("init")
        .arg(temp_path)
        .assert()
        .success();
    
    // Create test JUnit file
    let junit_path = temp_path.join("test.xml");
    fs::write(&junit_path, r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="2" failures="0" errors="0" time="0.1">
  <testsuite name="TestSuite1" tests="2" failures="0" errors="0" skipped="0" time="0.1" timestamp="2023-01-01T00:00:00">
    <testcase name="test1" classname="TestClass1" time="0.05"></testcase>
    <testcase name="test2" classname="TestClass1" time="0.05"></testcase>
  </testsuite>
</testsuites>"#).unwrap();
    
    // Capture snapshot
    let output = Command::cargo_bin("junit-snapshot")
        .unwrap()
        .arg("capture")
        .arg(&junit_path)
        .arg("--name")
        .arg("baseline")
        .arg("--dir")
        .arg(temp_path)
        .output()
        .unwrap();
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    let id = stdout.lines()
        .find(|line| line.contains("Snapshot created with ID:"))
        .unwrap()
        .split("ID: ")
        .nth(1)
        .unwrap()
        .trim();
    
    // Compare identical file
    Command::cargo_bin("junit-snapshot")
        .unwrap()
        .arg("compare")
        .arg(&junit_path)
        .arg(id)
        .arg("--dir")
        .arg(temp_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("All tests match the baseline"));
}

#[test]
fn test_compare_different_files() {
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();
    
    // Initialize snapshot directory
    Command::cargo_bin("junit-snapshot")
        .unwrap()
        .arg("init")
        .arg(temp_path)
        .assert()
        .success();
    
    // Create baseline JUnit file
    let baseline_path = temp_path.join("baseline.xml");
    fs::write(&baseline_path, r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="3" failures="0" errors="0" time="0.1">
  <testsuite name="TestSuite1" tests="3" failures="0" errors="0" skipped="0" time="0.1" timestamp="2023-01-01T00:00:00">
    <testcase name="test1" classname="TestClass1" time="0.05"></testcase>
    <testcase name="test2" classname="TestClass1" time="0.05"></testcase>
    <testcase name="test3" classname="TestClass1" time="0.05"></testcase>
  </testsuite>
</testsuites>"#).unwrap();
    
    // Capture baseline snapshot
    let output = Command::cargo_bin("junit-snapshot")
        .unwrap()
        .arg("capture")
        .arg(&baseline_path)
        .arg("--name")
        .arg("baseline")
        .arg("--dir")
        .arg(temp_path)
        .output()
        .unwrap();
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    let id = stdout.lines()
        .find(|line| line.contains("Snapshot created with ID:"))
        .unwrap()
        .split("ID: ")
        .nth(1)
        .unwrap()
        .trim();
    
    // Create different JUnit file
    let different_path = temp_path.join("different.xml");
    fs::write(&different_path, r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="3" failures="1" errors="0" time="0.1">
  <testsuite name="TestSuite1" tests="3" failures="1" errors="0" skipped="0" time="0.1" timestamp="2023-01-01T00:00:00">
    <testcase name="test1" classname="TestClass1" time="0.05"></testcase>
    <testcase name="test2" classname="TestClass1" time="0.05">
      <failure message="Test failed" type="AssertionError">Assertion failed</failure>
    </testcase>
    <testcase name="test4" classname="TestClass1" time="0.05"></testcase>
  </testsuite>
</testsuites>"#).unwrap();
    
    // Compare different file
    Command::cargo_bin("junit-snapshot")
        .unwrap()
        .arg("compare")
        .arg(&different_path)
        .arg(id)
        .arg("--dir")
        .arg(temp_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Differences found!"))
        .stdout(predicate::str::contains("Different tests: 1"))
        .stdout(predicate::str::contains("New tests: 1"))
        .stdout(predicate::str::contains("Missing tests: 1"));
    
    // Test with fail-on-diff flag
    Command::cargo_bin("junit-snapshot")
        .unwrap()
        .arg("compare")
        .arg(&different_path)
        .arg(id)
        .arg("--dir")
        .arg(temp_path)
        .arg("--fail-on-diff")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Test results differ from baseline"));
}

#[test]
fn test_compare_diff_only_flag() {
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();
    
    // Initialize snapshot directory
    Command::cargo_bin("junit-snapshot")
        .unwrap()
        .arg("init")
        .arg(temp_path)
        .assert()
        .success();
    
    // Create baseline JUnit file
    let baseline_path = temp_path.join("baseline.xml");
    fs::write(&baseline_path, r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="3" failures="0" errors="0" time="0.1">
  <testsuite name="TestSuite1" tests="3" failures="0" errors="0" skipped="0" time="0.1" timestamp="2023-01-01T00:00:00">
    <testcase name="test1" classname="TestClass1" time="0.05"></testcase>
    <testcase name="test2" classname="TestClass1" time="0.05"></testcase>
    <testcase name="test3" classname="TestClass1" time="0.05"></testcase>
  </testsuite>
</testsuites>"#).unwrap();
    
    // Capture baseline snapshot
    let output = Command::cargo_bin("junit-snapshot")
        .unwrap()
        .arg("capture")
        .arg(&baseline_path)
        .arg("--name")
        .arg("baseline")
        .arg("--dir")
        .arg(temp_path)
        .output()
        .unwrap();
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    let id = stdout.lines()
        .find(|line| line.contains("Snapshot created with ID:"))
        .unwrap()
        .split("ID: ")
        .nth(1)
        .unwrap()
        .trim();
    
    // Create partially different JUnit file
    let different_path = temp_path.join("different.xml");
    fs::write(&different_path, r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="3" failures="1" errors="0" time="0.1">
  <testsuite name="TestSuite1" tests="3" failures="1" errors="0" skipped="0" time="0.1" timestamp="2023-01-01T00:00:00">
    <testcase name="test1" classname="TestClass1" time="0.05"></testcase>
    <testcase name="test2" classname="TestClass1" time="0.05">
      <failure message="Test failed" type="AssertionError">Assertion failed</failure>
    </testcase>
    <testcase name="test3" classname="TestClass1" time="0.05"></testcase>
  </testsuite>
</testsuites>"#).unwrap();
    
    // Compare with diff-only flag
    let output = Command::cargo_bin("junit-snapshot")
        .unwrap()
        .arg("compare")
        .arg(&different_path)
        .arg(id)
        .arg("--dir")
        .arg(temp_path)
        .arg("--diff-only")
        .output()
        .unwrap();
    
    let stdout = String::from_utf8(output.stdout).unwrap();
    
    // Should show the different test
    assert!(stdout.contains("test2"));
    
    // Should not show the matching tests
    assert!(!stdout.contains("✓ test1"));
    assert!(!stdout.contains("✓ test3"));
}
