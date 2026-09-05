use interenv::shredder::TempFileGuard;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_edit_crash_recovery_cleanup() {
    let mut temp = NamedTempFile::new().unwrap();
    temp.write_all(b"KEY_BEING_EDITED=temporary_state").unwrap();
    let path = temp.path().to_path_buf();
    assert!(path.exists());

    let path_clone = path.clone();
    // Simulate an aborted edit session via unwinding
    let _ = std::panic::catch_unwind(move || {
        let _guard = TempFileGuard::new(path_clone);
        // Simulate editor crash or abort
        panic!("SIGINT / aborted session");
    });

    assert!(
        !path.exists(),
        "Temporary editing file must be destroyed when edit session crashes"
    );
}
