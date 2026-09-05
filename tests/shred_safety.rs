use interenv::shredder::{shred_file, TempFileGuard};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_shred_safety_normal() {
    let mut temp = NamedTempFile::new().unwrap();
    temp.write_all(b"CONFIDENTIAL_DATA=12345").unwrap();
    let path = temp.path().to_path_buf();
    assert!(path.exists());

    shred_file(&path).unwrap();
    assert!(!path.exists(), "File must not exist after shred_file");
}

#[test]
fn test_temp_file_guard_on_panic() {
    let mut temp = NamedTempFile::new().unwrap();
    temp.write_all(b"SENSITIVE_BUFFER=secret").unwrap();
    let path = temp.path().to_path_buf();
    assert!(path.exists());

    let path_clone = path.clone();
    let result = std::panic::catch_unwind(move || {
        let _guard = TempFileGuard::new(path_clone);
        panic!("Simulated editor panic!");
    });

    assert!(result.is_err());
    assert!(
        !path.exists(),
        "File must be shredded and unlinked even when a panic occurs!"
    );
}
