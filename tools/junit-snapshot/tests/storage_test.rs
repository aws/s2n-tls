use junit_snapshot::{
    parse_junit_file, Snapshot, SnapshotStorage, generate_snapshot_id
};
use std::path::Path;
use tempfile::tempdir;

#[test]
#[ignore = "Missing test file: integrationv2_happy_path.xml"]
fn test_snapshot_storage() {
    // Create a temporary directory for testing
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let temp_path = temp_dir.path();
    
    // Initialize the snapshot storage
    let mut storage = SnapshotStorage::init(temp_path).expect("Failed to initialize storage");
    
    // Parse a JUnit XML file
    let test_file = Path::new("tests/integrationv2_happy_path.xml");
    let test_results = parse_junit_file(test_file).expect("Failed to parse integrationv2_happy_path.xml");
    
    // Create a snapshot
    let id = generate_snapshot_id();
    let snapshot = Snapshot::new(
        id.clone(),
        Some("Test Snapshot".to_string()),
        Some("A test snapshot".to_string()),
        test_file.to_path_buf(),
        test_results,
    );
    
    // Save the snapshot
    storage.save_snapshot(&snapshot).expect("Failed to save snapshot");
    
    // Check if the snapshot exists
    assert!(storage.snapshot_exists(&id), "Snapshot should exist");
    
    // Load the snapshot
    let loaded_snapshot = storage.load_snapshot(&id).expect("Failed to load snapshot");
    
    // Verify the loaded snapshot
    assert_eq!(loaded_snapshot.id, id);
    assert_eq!(loaded_snapshot.name, Some("Test Snapshot".to_string()));
    assert_eq!(loaded_snapshot.description, Some("A test snapshot".to_string()));
    
    // Get snapshot summaries
    let summaries = storage.get_snapshot_summaries();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].id, id);
    
    // Delete the snapshot
    storage.delete_snapshot(&id).expect("Failed to delete snapshot");
    
    // Check that the snapshot no longer exists
    assert!(!storage.snapshot_exists(&id), "Snapshot should not exist after deletion");
    
    // Verify that the summary was also removed
    let summaries = storage.get_snapshot_summaries();
    assert_eq!(summaries.len(), 0);
}
