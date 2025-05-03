use junit_snapshot::{
    parse_junit_file, Snapshot, SnapshotStorage, generate_timestamp_id
};
use std::path::Path;
use tempfile::tempdir;

#[test]
fn test_snapshot_integration() {
    // Create a temporary directory for testing
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let temp_path = temp_dir.path();
    
    // Initialize the snapshot storage
    let mut storage = SnapshotStorage::init(temp_path).expect("Failed to initialize storage");
    
    // Test files to snapshot
    let test_files = [
        "integrationv2_sni_match.xml",
        "integrationv2_ocsp.xml",
        "integrationv2_key_update.xml",
        "integrationv2_serialization.xml"
    ];
    
    // Create and save snapshots for each test file
    for (i, file_name) in test_files.iter().enumerate() {
        let file_path_str = format!("tests/{}", file_name);
        let file_path = Path::new(&file_path_str);
        
        // Parse the JUnit XML file
        let test_results = parse_junit_file(file_path)
            .expect(&format!("Failed to parse {}", file_name));
        
        // Create a snapshot
        let id = generate_timestamp_id();
        let snapshot = Snapshot::new(
            id.clone(),
            Some(format!("Test Snapshot {}", i + 1)),
            Some(format!("A test snapshot for {}", file_name)),
            file_path.to_path_buf(),
            test_results.clone(),
        );
        
        // Save the snapshot
        storage.save_snapshot(&snapshot)
            .expect(&format!("Failed to save snapshot for {}", file_name));
        
        // Verify the snapshot exists
        assert!(storage.snapshot_exists(&id), "Snapshot for {} should exist", file_name);
        
        // Load and verify the snapshot
        let loaded_snapshot = storage.load_snapshot(&id)
            .expect(&format!("Failed to load snapshot for {}", file_name));
        
        // Verify the loaded snapshot
        assert_eq!(loaded_snapshot.id, id);
        assert_eq!(loaded_snapshot.name, Some(format!("Test Snapshot {}", i + 1)));
        assert_eq!(loaded_snapshot.description, Some(format!("A test snapshot for {}", file_name)));
        
        // Verify test results match
        assert_eq!(loaded_snapshot.test_results.tests, test_results.tests);
        assert_eq!(loaded_snapshot.test_results.failures, test_results.failures);
        assert_eq!(loaded_snapshot.test_results.errors, test_results.errors);
        
        println!("Successfully created and verified snapshot for {}", file_name);
    }
    
    // Get all snapshot summaries
    let summaries = storage.get_snapshot_summaries();
    assert_eq!(summaries.len(), test_files.len(), "Should have created {} snapshots", test_files.len());
    
    println!("All {} snapshots created and verified successfully", test_files.len());
}
