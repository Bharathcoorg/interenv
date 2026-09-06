use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// RAII Guard that automatically shreds and unlinks a sensitive temporary file on drop.
#[derive(Debug)]
pub struct TempFileGuard {
    /// Path to the protected temporary file.
    path: PathBuf,
}

impl TempFileGuard {
    /// Create a new `TempFileGuard` wrapping a temporary file path.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Access the protected temporary file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = shred_file(&self.path);
        let _ = fs::remove_file(&self.path);
    }
}

/// Securely overwrite and delete a sensitive plaintext file from disk.
/// Performs a 3-pass `DoD` 5220.22-M style overwrite:
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

    let meta = match fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) => return Err(format!("Cannot read metadata for {}: {}", p.display(), e)),
    };

    if meta.file_type().is_symlink() {
        return Err(format!("Refusing to shred symlink: {}", p.display()));
    }

    let file_len = meta.len() as usize;

    if file_len > 0 {
        // Pass 1: All 0x00
        overwrite_pattern(p, file_len, 0x00)?;

        // Pass 2: All 0xFF
        overwrite_pattern(p, file_len, 0xFF)?;

        // Pass 3: CSPRNG Random Bytes
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(p)
                .map_err(|e| format!("Cannot open file for shredding: {}", e))?
        };

        #[cfg(not(unix))]
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

    platform_post_shred(p)?;

    // Delete file from disk
    fs::remove_file(p)
        .map_err(|e| format!("Failed to delete shredded file {}: {}", p.display(), e))?;

    Ok(())
}

#[cfg(windows)]
fn platform_post_shred(path: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        FindClose, FindFirstStreamW, FindNextStreamW, FlushFileBuffers, SetEndOfFile,
        WIN32_FIND_STREAM_DATA,
    };

    if let Ok(file) = OpenOptions::new().write(true).open(path) {
        let handle = HANDLE(file.as_raw_handle() as _);
        // SAFETY: handle is derived from a valid open file with write permissions.
        // SetEndOfFile truncates the file allocation and FlushFileBuffers commits writes to physical disk.
        // SetFileValidData is omitted because it requires SE_MANAGE_VOLUME_NAME privilege not held by standard users.
        unsafe {
            let _ = SetEndOfFile(handle);
            let _ = FlushFileBuffers(handle);
        }
    }

    let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide_path.push(0);

    // SAFETY: FindFirstStreamW and FindNextStreamW operate on a valid null-terminated
    // wide path string and write stream info into find_data.
    unsafe {
        let mut find_data = WIN32_FIND_STREAM_DATA::default();
        let handle_res = FindFirstStreamW(
            windows::core::PCWSTR(wide_path.as_ptr()),
            windows::Win32::Storage::FileSystem::FindStreamInfoStandard,
            &mut find_data as *mut _ as _,
            0,
        );

        if let Ok(stream_handle) = handle_res {
            let mut more = true;
            while more {
                let stream_name = String::from_utf16_lossy(&find_data.cStreamName);
                let trimmed_name = stream_name.trim_matches('\0');
                if !trimmed_name.is_empty()
                    && trimmed_name != "::$DATA"
                    && trimmed_name.chars().all(|c| {
                        c.is_alphanumeric() || c == ':' || c == '_' || c == '-' || c == '$'
                    })
                {
                    let ads_path_str = format!("{}:{}", path.display(), trimmed_name);
                    let _ = std::fs::remove_file(&ads_path_str);
                }
                more = FindNextStreamW(stream_handle, &mut find_data as *mut _ as _).is_ok();
            }
            let _ = FindClose(stream_handle);
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn platform_post_shred(path: &Path) -> Result<(), String> {
    use std::os::unix::io::AsRawFd;
    if let Ok(file) = OpenOptions::new().write(true).open(path) {
        let fd = file.as_raw_fd();
        let len = file.metadata().map(|m| m.len() as i64).unwrap_or(0);
        if len > 0 {
            // SAFETY: fallocate and ioctl are invoked with a valid open file
            // descriptor and length. Their return values are checked: a
            // failure means the platform decommit did not happen, so we
            // surface it rather than silently reporting success.
            unsafe {
                // FALLOC_FL_ZERO_RANGE (0x10) | FALLOC_FL_KEEP_SIZE (0x01) = 0x11.
                let fa_ret = libc::fallocate(fd, 0x10 | 0x01, 0, len);
                if fa_ret != 0 {
                    let err = std::io::Error::last_os_error();
                    eprintln!(
                        "⚠️  Filesystem zero-range decommit failed for {}: {} (shredder: partial)",
                        path.display(),
                        err
                    );
                }

                // Only attempt BLKDISCARD on a block device. The ioctl number is
                // architecture-dependent, so compute it with _IOWR rather than
                // hard-coding a magic value that may be wrong on another arch.
                let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
                if libc::fstat(fd, st.as_mut_ptr()) == 0 {
                    let st = st.assume_init();
                    if (st.st_mode & libc::S_IFMT) == libc::S_IFBLK {
                        let mut range: [u64; 2] = [0, len as u64];
                        // BLKDISCARD is `_IOWR(0x12, 1, struct fstrim_range)` in the
                        // Linux kernel. The ioctl command byte is 0x12 and the size
                        // is that of `struct fstrim_range` (two u64s). Computing it
                        // with _IOWR makes the value correct on every architecture;
                        // the previously hard-coded `0x1277` was missing the
                        // direction and size bits and would have been a no-op.
                        let blkdiscard: libc::c_ulong = libc::_IOWR(
                            0x12 as libc::c_ulong,
                            1,
                            std::mem::size_of::<[u64; 2]>() as libc::c_ulong,
                        );
                        let io_ret = libc::ioctl(fd, blkdiscard, range.as_mut_ptr());
                        if io_ret != 0 {
                            let err = std::io::Error::last_os_error();
                            eprintln!(
                                "⚠️  Block-device BLKDISCARD failed for {}: {} (shredder: partial)",
                                path.display(),
                                err
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn platform_post_shred(path: &Path) -> Result<(), String> {
    use std::os::unix::io::AsRawFd;
    if let Ok(file) = OpenOptions::new().write(true).open(path) {
        let fd = file.as_raw_fd();
        // SAFETY: fcntl 51 (F_FULLFSYNC) flushes write buffers to non-volatile storage.
        unsafe {
            let _ = libc::fcntl(fd, 51);
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn platform_post_shred(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn overwrite_pattern(path: &Path, file_len: usize, byte_val: u8) -> Result<(), String> {
    let meta = fs::symlink_metadata(path)
        .map_err(|e| format!("Cannot read metadata for {}: {}", path.display(), e))?;
    if meta.file_type().is_symlink() {
        return Err(format!("Refusing to overwrite symlink: {}", path.display()));
    }

    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| format!("Cannot open file: {}", e))?
    };

    #[cfg(not(unix))]
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
