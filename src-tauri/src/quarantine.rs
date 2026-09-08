//! Captured-binary quarantine — AGENTS.md hard constraint #2.
//!
//! Responsibilities:
//! - On capture: immediately `chmod 000` + `.isolated` suffix on the file.
//!   The captured binary is NEVER executed on the host, ever.
//! - VirusTotal submissions default to **hash-only** (SHA-256). Full-file
//!   upload requires an explicit per-file operator opt-in in the UI — never
//!   a default code path.
//! - The hex viewer opens files as read-only byte streams; the UI never calls
//!   an OS "open with" or execute action on a captured sample.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};
use std::io::Read;

#[derive(Debug)]
pub enum QuarantineError {
    IoError(std::io::Error),
    HashError(String),
}

impl From<std::io::Error> for QuarantineError {
    fn from(err: std::io::Error) -> Self {
        QuarantineError::IoError(err)
    }
}

pub struct QuarantineManager {
    quarantine_dir: PathBuf,
}

impl QuarantineManager {
    pub fn new(app_data_dir: &Path) -> Result<Self, QuarantineError> {
        let quarantine_dir = app_data_dir.join("quarantine");
        if !quarantine_dir.exists() {
            fs::create_dir_all(&quarantine_dir)?;
        }
        Ok(Self { quarantine_dir })
    }

    /// Isolates a captured payload (HC#2).
    ///
    /// 1. Hashes the file (SHA-256).
    /// 2. Moves/Copies it to the quarantine directory with a `.isolated` extension.
    /// 3. Sets permissions to prevent execution.
    pub fn isolate_file(&self, source_path: &Path) -> Result<(String, PathBuf), QuarantineError> {
        let mut file = fs::File::open(source_path)?;
        
        // 1. Hash the file
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let hash_result = hasher.finalize();
        let sha256_hash = hex::encode(hash_result);

        // 2. Move to secure dir with .isolated
        let dest_filename = format!("{}.isolated", sha256_hash);
        let dest_path = self.quarantine_dir.join(dest_filename);

        // We copy instead of move just in case it's on a different mount/volume.
        fs::copy(source_path, &dest_path)?;

        // 3. Prevent execution
        let mut perms = fs::metadata(&dest_path)?.permissions();
        perms.set_readonly(true); // Windows compatible
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o000); // chmod 000
        }
        
        fs::set_permissions(&dest_path, perms)?;

        // If it was a copy, delete the original
        let _ = fs::remove_file(source_path);

        Ok((sha256_hash, dest_path))
    }
}
