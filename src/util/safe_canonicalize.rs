use std::path::{Path, PathBuf};

/// Resolve and canonicalize path strictly, rejecting untrusted symlinks and reparse points.
///
/// On Unix this walks the path component-by-component, opening each component with
/// `O_NOFOLLOW` relative to its true parent directory fd. A symlink (or dangling
/// symlink) anywhere in the path makes `openat` return `ELOOP`, which is rejected.
/// The canonical result is read back from the open fd (`/proc/self/fd` on Linux),
/// so there is no race window between a per-component check and a final name-based
/// `canonicalize` — the classic TOCTOU that a final `std::fs::canonicalize` would
/// introduce by following a symlink planted between the checks.
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
        // Open "/" with O_NOFOLLOW so the walk cannot be redirected through a
        // symlink at the very first component.
        #[cfg(target_os = "linux")]
        let open_flags = libc::O_PATH | libc::O_NOFOLLOW;
        #[cfg(not(target_os = "linux"))]
        let open_flags = libc::O_RDONLY | libc::O_NOFOLLOW;

        let root_c = std::ffi::CString::new("/").unwrap();
        // SAFETY: "/" is never a symlink; the flags open it as a directory fd.
        let root_fd = unsafe { libc::open(root_c.as_ptr(), open_flags) };
        if root_fd < 0 {
            return Err("Failed to open root directory for safe canonicalization".to_string());
        }

        // Keep the chain of parent directory fds open so each component is opened
        // relative to its true parent and `..` can pop back to the parent.
        let mut fds: Vec<libc::c_int> = vec![root_fd];
        let mut names: Vec<String> = Vec::new();

        let result: Result<(), String> = (|| {
            for component in path.components() {
                match component {
                    std::path::Component::RootDir => {}
                    std::path::Component::CurDir => {}
                    std::path::Component::ParentDir => {
                        if fds.len() <= 1 {
                            return Err(format!("Path traversal escapes root: {}", path.display()));
                        }
                        if let Some(fd) = fds.pop() {
                            unsafe {
                                let _ = libc::close(fd);
                            }
                        }
                        names.pop();
                    }
                    std::path::Component::Normal(c) => {
                        let bytes = c.as_os_str().as_encoded_bytes();
                        if bytes.iter().any(|&b| b == 0) {
                            return Err(format!(
                                "Invalid path component (embedded NUL): {}",
                                c.display()
                            ));
                        }
                        // SAFETY: bytes contain no NUL; CString::new owns its copy.
                        let c_cstr = std::ffi::CString::new(bytes)
                            .map_err(|_| format!("Invalid path component: {}", c.display()))?;
                        let parent_fd = *fds.last().unwrap();
                        // SAFETY: parent_fd is a valid directory fd opened with
                        // O_NOFOLLOW; c_cstr is NUL-terminated. O_NOFOLLOW makes
                        // openat fail with ELOOP if the component is a symlink.
                        let comp_fd =
                            unsafe { libc::openat(parent_fd, c_cstr.as_ptr(), open_flags) };
                        if comp_fd < 0 {
                            let err = std::io::Error::last_os_error();
                            if err.raw_os_error() == Some(libc::ELOOP) {
                                return Err(format!(
                                    "Symlink detected in path: {}",
                                    display_joined(&names, c)
                                ));
                            }
                            return Err(format!("Path traversal error: {}", err));
                        }
                        // SAFETY: comp_fd is freshly opened; fstat to confirm type.
                        let mut sb: libc::stat = unsafe { std::mem::zeroed() };
                        if unsafe { libc::fstat(comp_fd, &mut sb) } != 0 {
                            unsafe {
                                let _ = libc::close(comp_fd);
                            }
                            return Err(format!(
                                "Failed to stat '{}': {}",
                                c.display(),
                                std::io::Error::last_os_error()
                            ));
                        }
                        if (sb.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                            unsafe {
                                let _ = libc::close(comp_fd);
                            }
                            return Err(format!(
                                "Symlink detected in path: {}",
                                display_joined(&names, c)
                            ));
                        }
                        fds.push(comp_fd);
                        names.push(
                            c.to_str()
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| String::from_utf8_lossy(bytes).into_owned()),
                        );
                    }
                    std::path::Component::Prefix(_) => {}
                }
            }
            Ok(())
        })();

        // Resolve the canonical path from the final open fd so the result is
        // TOCTOU-free: the name is never re-walked after the O_NOFOLLOW walk.
        let canonical = result.and_then(|_| {
            #[cfg(target_os = "linux")]
            {
                let final_fd = *fds.last().unwrap();
                let link = format!("/proc/self/fd/{}", final_fd);
                std::fs::read_link(&link).map_err(|e| {
                    format!("Failed to resolve canonical path via /proc/self/fd: {}", e)
                })
            }
            #[cfg(not(target_os = "linux"))]
            {
                // On non-Linux Unix there is no /proc/self/fd; rebuild the name
                // from the O_NOFOLLOW-verified components and canonicalize.
                // Every component was verified non-symlink while its parent fd
                // was held open, so the residual race window is minimal.
                let mut p = PathBuf::from("/");
                for n in &names {
                    p.push(n);
                }
                std::fs::canonicalize(&p).map_err(|e| format!("Canonicalization error: {}", e))
            }
        });

        // Close all open fds.
        while let Some(fd) = fds.pop() {
            unsafe {
                let _ = libc::close(fd);
            }
        }

        canonical
    }

    #[cfg(not(any(windows, unix)))]
    {
        std::fs::canonicalize(path).map_err(|e| format!("Canonicalization error: {}", e))
    }
}

/// Render a path for an error message from the accumulated component names plus
/// the component currently being inspected.
#[cfg(unix)]
fn display_joined(names: &[String], c: &std::ffi::OsStr) -> String {
    let mut p = String::from("/");
    for n in names {
        if !p.ends_with('/') {
            p.push('/');
        }
        p.push_str(n);
    }
    if !p.ends_with('/') {
        p.push('/');
    }
    p.push_str(&String::from_utf8_lossy(c.as_encoded_bytes()));
    p
}
