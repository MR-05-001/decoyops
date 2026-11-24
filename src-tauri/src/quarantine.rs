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

use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

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

    pub fn quarantine_dir(&self) -> &Path {
        &self.quarantine_dir
    }

    /// Isolates a captured payload (HC#2).
    ///
    /// 1. Hashes the file (SHA-256).
    /// 2. Atomically creates the destination file with a `.isolated` extension (`create_new(true)`).
    /// 3. Sets permissions to prevent execution (`readonly` on Windows, `0o000` on Unix).
    pub fn isolate_file(&self, source_path: &Path) -> Result<(String, PathBuf), QuarantineError> {
        if !self.quarantine_dir.exists() {
            fs::create_dir_all(&self.quarantine_dir)?;
        }

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

        // 2. Move to secure dir with .isolated atomically to prevent TOCTOU overwrite races
        let dest_filename = format!("{}.isolated", sha256_hash);
        let dest_path = self.quarantine_dir.join(dest_filename);

        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest_path)
        {
            Ok(mut dest_file) => {
                file.seek(SeekFrom::Start(0))?;
                std::io::copy(&mut file, &mut dest_file)?;
                dest_file.sync_all()?;
                drop(dest_file);

                // 3. Prevent execution
                let mut perms = fs::metadata(&dest_path)?.permissions();
                perms.set_readonly(true); // Windows compatible

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    perms.set_mode(0o000); // chmod 000
                }

                fs::set_permissions(&dest_path, perms)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Payload with identical SHA-256 already quarantined; keep existing isolated file.
            }
            Err(e) => return Err(QuarantineError::IoError(e)),
        }

        drop(file);
        // Clean up the original temporary source file; propagate error so locked files
        // are not repeatedly re-ingested into captured_files.
        fs::remove_file(source_path)?;

        Ok((sha256_hash, dest_path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn isolate_file_hashes_locks_and_deduplicates() {
        let base = std::env::temp_dir().join(format!("decoyops_q_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        let mgr = QuarantineManager::new(&base).unwrap();
        let src1 = base.join("sample1.bin");
        let src2 = base.join("sample2.bin");
        fs::File::create(&src1)
            .unwrap()
            .write_all(b"evil_payload")
            .unwrap();
        fs::File::create(&src2)
            .unwrap()
            .write_all(b"evil_payload")
            .unwrap();

        let (hash1, iso1) = mgr.isolate_file(&src1).unwrap();
        assert!(!src1.exists(), "source file should be removed");
        assert!(iso1.exists(), "isolated file should exist");
        assert!(iso1.to_string_lossy().ends_with(".isolated"));
        assert!(fs::metadata(&iso1).unwrap().permissions().readonly());

        let (hash2, iso2) = mgr.isolate_file(&src2).unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(iso1, iso2);
        assert!(!src2.exists(), "duplicate source should also be cleaned up");

        let mut perms = fs::metadata(&iso1).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        let _ = fs::set_permissions(&iso1, perms);
        let _ = fs::remove_dir_all(&base);
    }
}
