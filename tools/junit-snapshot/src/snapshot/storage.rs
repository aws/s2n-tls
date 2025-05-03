use crate::snapshot::model::{Snapshot, SnapshotCollection, SnapshotSummary};
use anyhow::{Context, Result};
use serde_json;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use thiserror::Error;

const SNAPSHOTS_DIR: &str = ".snapshots";
const COLLECTION_FILE: &str = "collection.json";

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Failed to create directory: {0}")]
    DirectoryCreationError(String),
    
    #[error("Failed to read file: {0}")]
    FileReadError(String),
    
    #[error("Failed to write file: {0}")]
    FileWriteError(String),
    
    #[error("Failed to serialize data: {0}")]
    SerializationError(String),
    
    #[error("Failed to deserialize data: {0}")]
    DeserializationError(String),
    
    #[error("Snapshot not found: {0}")]
    SnapshotNotFound(String),
}

/// Manages the storage of snapshots
pub struct SnapshotStorage {
    /// Base directory for snapshots
    base_dir: PathBuf,
    
    /// Collection of snapshots
    collection: SnapshotCollection,
}

impl SnapshotStorage {
    /// Create a new snapshot storage
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self> {
        let base_dir = base_dir.as_ref().join(SNAPSHOTS_DIR);
        
        // Create the snapshots directory if it doesn't exist
        fs::create_dir_all(&base_dir)
            .with_context(|| format!("Failed to create snapshots directory: {:?}", base_dir))
            .map_err(|e| StorageError::DirectoryCreationError(e.to_string()))?;
        
        // Try to load the collection file, or create a new one
        let collection_path = base_dir.join(COLLECTION_FILE);
        let collection = if collection_path.exists() {
            Self::load_collection(&collection_path)?
        } else {
            let collection = SnapshotCollection::new("Test Snapshots".to_string());
            Self::save_collection_file(&collection_path, &collection)?;
            collection
        };
        
        Ok(Self { base_dir, collection })
    }
    
    /// Initialize a new snapshot storage
    pub fn init<P: AsRef<Path>>(base_dir: P) -> Result<Self> {
        let storage = Self::new(base_dir)?;
        
        // Create necessary subdirectories
        let snapshots_dir = storage.base_dir.join("snapshots");
        fs::create_dir_all(&snapshots_dir)
            .with_context(|| format!("Failed to create snapshots subdirectory: {:?}", snapshots_dir))
            .map_err(|e| StorageError::DirectoryCreationError(e.to_string()))?;
        
        Ok(storage)
    }
    
    /// Save a snapshot
    pub fn save_snapshot(&mut self, snapshot: &Snapshot) -> Result<()> {
        // Create the snapshot file path
        let snapshot_path = self.get_snapshot_path(&snapshot.id);
        
        // Ensure the parent directory exists
        if let Some(parent) = snapshot_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {:?}", parent))
                .map_err(|e| StorageError::DirectoryCreationError(e.to_string()))?;
        }
        
        // Save the snapshot to a file
        let file = File::create(&snapshot_path)
            .with_context(|| format!("Failed to create snapshot file: {:?}", snapshot_path))
            .map_err(|e| StorageError::FileWriteError(e.to_string()))?;
        
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, snapshot)
            .with_context(|| "Failed to serialize snapshot")
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        
        // Update the collection
        let summary = snapshot.get_summary();
        self.collection.add_snapshot(summary);
        
        // Save the updated collection
        self.save_collection()?;
        
        Ok(())
    }
    
    /// Load a snapshot by ID
    pub fn load_snapshot(&self, id: &str) -> Result<Snapshot> {
        let snapshot_path = self.get_snapshot_path(id);
        
        if !snapshot_path.exists() {
            return Err(StorageError::SnapshotNotFound(id.to_string()).into());
        }
        
        let file = File::open(&snapshot_path)
            .with_context(|| format!("Failed to open snapshot file: {:?}", snapshot_path))
            .map_err(|e| StorageError::FileReadError(e.to_string()))?;
        
        let reader = BufReader::new(file);
        let snapshot = serde_json::from_reader(reader)
            .with_context(|| "Failed to deserialize snapshot")
            .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
        
        Ok(snapshot)
    }
    
    /// Delete a snapshot by ID
    pub fn delete_snapshot(&mut self, id: &str) -> Result<()> {
        let snapshot_path = self.get_snapshot_path(id);
        
        if !snapshot_path.exists() {
            return Err(StorageError::SnapshotNotFound(id.to_string()).into());
        }
        
        // Remove the snapshot file
        fs::remove_file(&snapshot_path)
            .with_context(|| format!("Failed to delete snapshot file: {:?}", snapshot_path))
            .map_err(|e| StorageError::FileWriteError(e.to_string()))?;
        
        // Update the collection
        self.collection.remove_snapshot(id);
        
        // Save the updated collection
        self.save_collection()?;
        
        Ok(())
    }
    
    /// Get all snapshot summaries
    pub fn get_snapshot_summaries(&self) -> Vec<SnapshotSummary> {
        self.collection.snapshots.clone()
    }
    
    /// Check if a snapshot exists
    pub fn snapshot_exists(&self, id: &str) -> bool {
        self.get_snapshot_path(id).exists()
    }
    
    /// Get the path for a snapshot file
    fn get_snapshot_path(&self, id: &str) -> PathBuf {
        self.base_dir.join("snapshots").join(format!("{}.json", id))
    }
    
    /// Load the collection file
    fn load_collection<P: AsRef<Path>>(path: P) -> Result<SnapshotCollection> {
        let file = File::open(path)
            .with_context(|| "Failed to open collection file")
            .map_err(|e| StorageError::FileReadError(e.to_string()))?;
        
        let reader = BufReader::new(file);
        let collection = serde_json::from_reader(reader)
            .with_context(|| "Failed to deserialize collection")
            .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
        
        Ok(collection)
    }
    
    /// Save the collection file
    fn save_collection_file<P: AsRef<Path>>(path: P, collection: &SnapshotCollection) -> Result<()> {
        let file = File::create(path)
            .with_context(|| "Failed to create collection file")
            .map_err(|e| StorageError::FileWriteError(e.to_string()))?;
        
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, collection)
            .with_context(|| "Failed to serialize collection")
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        
        Ok(())
    }
    
    /// Save the current collection
    fn save_collection(&self) -> Result<()> {
        let collection_path = self.base_dir.join(COLLECTION_FILE);
        Self::save_collection_file(&collection_path, &self.collection)
    }
}
