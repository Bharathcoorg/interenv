use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// RAII Guard that automatically shreds and unlinks a sensitive temporary file on drop.
#[derive(Debug)]
pub struct TempFileGuard {
    pub path: PathBuf,
}

impl TempFileGuard {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = shred_file(&self.path);
        let _ = fs::remove_file(&self.path);
    }
}

/// Securely overwrite and delete a sensitive plaintext file from disk.
/// Performs a 3-pass DoD 5220.22-M style overwrite:
/// 1. Overwrite with 0x00
/// 2. Overwrite with 0xFF
/// 3. Overwrite with cryptographically secure random bytes
///
/// Followed by flushing to physical storage, truncating to 0 bytes, and unlinking.
pub fn shred_file<P: AsRef<Path>>(path: P) -> Result<(), String> {
    let p = path.as_ref();
    if !p.exists() {
        return Ok(());
    }

    let metadata = fs::metadata(p).map_err(|e| format!("Cannot read file metadata: {}", e))?;
    let file_len = metadata.len() as usize;

    if file_len > 0 {
        // Pass 1: Zeroes
        overwrite_pattern(p, file_len, 0x00)?;

        // Pass 2: Ones
        overwrite_pattern(p, file_len, 0xFF)?;

        // Pass 3: Random cryptosecure bytes
        let mut file = OpenOptions::new()
            .write(true)
            .open(p)
            .map_err(|e| format!("Cannot open file for shredding: {}", e))?;

        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("Seek error: {}", e))?;

        let mut random_buf = vec![0u8; file_len.min(64 * 1024)];
        let mut written = 0;
        while written < file_len {
            let chunk_size = (file_len - written).min(random_buf.len());
            OsRng.fill_bytes(&mut random_buf[..chunk_size]);
            file.write_all(&random_buf[..chunk_size])
                .map_err(|e| format!("Random overwrite error: {}", e))?;
            written += chunk_size;
        }
        file.sync_all().map_err(|e| format!("Sync error: {}", e))?;
    }

    // Truncate to zero bytes
    let _ = OpenOptions::new().write(true).truncate(true).open(p);

    // Delete file from disk
    fs::remove_file(p)
        .map_err(|e| format!("Failed to delete shredded file {}: {}", p.display(), e))?;

    Ok(())
}

fn overwrite_pattern(path: &Path, file_len: usize, byte_val: u8) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("Cannot open file: {}", e))?;

    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("Seek error: {}", e))?;

    let buf_size = file_len.min(64 * 1024);
    let buf = vec![byte_val; buf_size];

    let mut written = 0;
    while written < file_len {
        let chunk_size = (file_len - written).min(buf.len());
        file.write_all(&buf[..chunk_size])
            .map_err(|e| format!("Overwrite error: {}", e))?;
        written += chunk_size;
    }
    file.sync_all().map_err(|e| format!("Sync error: {}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_shred_file() {
        let mut temp = NamedTempFile::new().unwrap();
        temp.write_all(b"SUPER_SECRET_KEY=123456789").unwrap();
        let path = temp.path().to_path_buf();

        assert!(path.exists());
        shred_file(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn test_temp_file_guard() {
        let temp = NamedTempFile::new().unwrap();
        let path = temp.path().to_path_buf();
        assert!(path.exists());

        {
            let _guard = TempFileGuard::new(path.clone());
        } // guard drops here

        assert!(
            !path.exists(),
            "File must be deleted after TempFileGuard drops"
        );
    }
}
