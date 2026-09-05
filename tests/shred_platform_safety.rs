use interenv::shredder::shred_file;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_shred_platform_safety() {
    let mut temp = NamedTempFile::new().unwrap();
    temp.write_all(b"PLATFORM_SHRED_DATA_CONTENT_12345")
        .unwrap();
    let path = temp.path().to_path_buf();
    assert!(path.exists());

    let shred_res = shred_file(&path);
    assert!(
        shred_res.is_ok(),
        "shred_file failed: {:?}",
        shred_res.err()
    );
    assert!(!path.exists(), "File must not exist after shred_file");
}
