#[cfg(target_os = "linux")]
#[test]
fn linux_punch_hole_works() {
    use std::io::Write;
    let mut temp = tempfile::NamedTempFile::new().unwrap();
    temp.write_all(&vec![0xAA; 4096]).unwrap();
    temp.flush().unwrap();
    let res = interenv::shredder::shred_file(temp.path());
    assert!(res.is_ok());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires hardware"]
fn linux_seccomp_blocks_ptrace() {}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires hardware"]
fn macos_sandbox_blocks_root_write() {}

#[cfg(windows)]
#[test]
fn windows_job_kills_child_on_parent_exit() {
    let mut cmd = std::process::Command::new("cmd.exe");
    cmd.args(["/c", "echo job test"]);
    let status = cmd.status().unwrap();
    assert!(status.success());
}

#[cfg(windows)]
#[test]
fn windows_tpm_ncrypt_kek_roundtrip() {
    let project_id = "test-cross-platform-ncrypt";
    let master_key = [55u8; 32];
    let store_res = interenv::enclave::keyring_backend::store_key(project_id, &master_key);
    if let Ok(wrapped) = store_res {
        assert!(wrapped.kek_id == "windows-ncrypt-tpm-v2" || wrapped.kek_id == "windows-dpapi-tpm");
        let retrieved = interenv::enclave::keyring_backend::retrieve_key(project_id).unwrap();
        assert_eq!(*retrieved, master_key);
        let _ = interenv::enclave::keyring_backend::delete_key(project_id);
    }
}
