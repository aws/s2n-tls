use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cli_capture_and_list() {
    // Create a temporary directory for testing
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let temp_path = temp_dir.path().to_str().unwrap();
    
    // Initialize the snapshot directory
    let init_output = Command::new("cargo")
        .args(["run", "--", "init", temp_path])
        .current_dir(".")
        .output()
        .expect("Failed to execute init command");
    
    assert!(init_output.status.success(), "Init command failed: {:?}", String::from_utf8_lossy(&init_output.stderr));
    println!("Successfully initialized snapshot directory");
    
    // Test files to capture
    let test_files = [
        "tests/integrationv2_sni_match.xml",
        "tests/integrationv2_key_update.xml"
    ];
    
    // Capture snapshots for each test file
    for (i, file_path) in test_files.iter().enumerate() {
        let name = format!("test-snapshot-{}", i + 1);
        let description = format!("Test snapshot {} description", i + 1);
        
        let capture_output = Command::new("cargo")
            .args([
                "run", "--", "capture", 
                file_path,
                "--name", &name,
                "--description", &description,
                "--dir", temp_path
            ])
            .current_dir(".")
            .output()
            .expect("Failed to execute capture command");
        
        assert!(capture_output.status.success(), 
                "Capture command failed for {}: {:?}", 
                file_path, 
                String::from_utf8_lossy(&capture_output.stderr));
        
        println!("Successfully captured snapshot for {}", file_path);
    }
    
    // List snapshots
    let list_output = Command::new("cargo")
        .args(["run", "--", "list", "--dir", temp_path])
        .current_dir(".")
        .output()
        .expect("Failed to execute list command");
    
    assert!(list_output.status.success(), "List command failed: {:?}", String::from_utf8_lossy(&list_output.stderr));
    
    let list_output_str = String::from_utf8_lossy(&list_output.stdout);
    println!("List output: {}", list_output_str);
    
    // Verify that snapshots were created (we don't check for specific names since they're timestamp-based)
    assert!(list_output_str.contains("Available snapshots:"), "No snapshots listed");
    assert!(list_output_str.contains("20"), "No timestamp-based IDs found");
    
    println!("Successfully verified CLI integration");
}
