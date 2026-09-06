use std::path::{Path, PathBuf};

/// Resolve and canonicalize path strictly, rejecting untrusted symlinks and reparse points.
pub fn safe_canonicalize(path: &Path) -> Result<PathBuf, String> {
    if !path.exists() {
        return Err(format!("Path does not exist: {}", path.display()));
    }

    #[cfg(windows)]
    {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Storage::FileSystem::{
            GetFinalPathNameByHandleW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_NAME_NORMALIZED, GETFINALPATHNAMEBYHANDLE_FLAGS, VOLUME_NAME_DOS,
        };

        let file = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(path)
            .map_err(|e| format!("Failed to open path for safe canonicalization: {}", e))?;

        let handle = windows::Win32::Foundation::HANDLE(file.as_raw_handle() as _);
        let mut buffer = vec![0u16; 1024];
        // SAFETY: GetFinalPathNameByHandleW receives a valid file handle and preallocated buffer.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                &mut buffer,
                GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0),
            )
        };

        if len == 0 {
            return Err("Failed to resolve final path on Windows".to_string());
        }

        let path_str = String::from_utf16_lossy(&buffer[..len as usize]);
        let clean_path = if let Some(stripped) = path_str.strip_prefix(r"\\?\") {
            stripped.to_string()
        } else {
            path_str
        };

        let mut check_curr = PathBuf::from(&clean_path);
        loop {
            if let Ok(metadata) = std::fs::symlink_metadata(&check_curr) {
                if metadata.file_type().is_symlink() {
                    return Err(format!(
                        "Symlink detected in path: {}",
                        check_curr.display()
                    ));
                }
            }
            if !check_curr.pop() {
                break;
            }
        }

        Ok(PathBuf::from(clean_path))
    }

    #[cfg(unix)]
    {
        let mut resolved = PathBuf::new();
        if path.is_absolute() {
            resolved.push("/");
        }

        for component in path.components() {
            match component {
                std::path::Component::RootDir => {}
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    resolved.pop();
                }
                std::path::Component::Normal(c) => {
                    resolved.push(c);
                    #[cfg(target_os = "macos")]
                    if resolved == Path::new("/var")
                        || resolved == Path::new("/tmp")
                        || resolved == Path::new("/etc")
                    {
                        continue;
                    }
                    let meta = std::fs::symlink_metadata(&resolved)
                        .map_err(|e| format!("Path traversal error: {}", e))?;
                    if meta.file_type().is_symlink() {
                        return Err(format!("Symlink detected in path: {}", resolved.display()));
                    }
                }
                std::path::Component::Prefix(_) => {}
            }
        }

        std::fs::canonicalize(&resolved).map_err(|e| format!("Canonicalization error: {}", e))
    }

    #[cfg(not(any(windows, unix)))]
    {
        std::fs::canonicalize(path).map_err(|e| format!("Canonicalization error: {}", e))
    }
}
