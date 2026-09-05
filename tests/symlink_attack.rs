use interenv::util::safe_canonicalize;
use tempfile::TempDir;

#[test]
fn test_symlink_attack_prevention() {
    let temp_dir = TempDir::new().unwrap();
    let real_dir = temp_dir.path().join("real_dir");
    std::fs::create_dir(&real_dir).unwrap();

    let target_file = real_dir.join("secret.txt");
    std::fs::write(&target_file, b"CONFIDENTIAL").unwrap();

    // Verify safe_canonicalize on valid non-symlink path
    let canonical = safe_canonicalize(&target_file);
    assert!(
        canonical.is_ok(),
        "Failed to safe_canonicalize regular file: {:?}",
        canonical.err()
    );

    // Try creating a symlink if the OS / environment permits
    let link_path = temp_dir.path().join("link_file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        if symlink(&target_file, &link_path).is_ok() {
            let res = safe_canonicalize(&link_path);
            assert!(res.is_err(), "safe_canonicalize must reject symlink paths");
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::symlink_file;
        if symlink_file(&target_file, &link_path).is_ok() {
            let res = safe_canonicalize(&link_path);
            assert!(res.is_err(), "safe_canonicalize must reject symlink paths");
        }
    }
}
