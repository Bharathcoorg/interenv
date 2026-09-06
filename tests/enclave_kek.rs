use interenv::enclave::keyring_backend::{delete_key, retrieve_key, store_key};

#[test]
fn test_enclave_kek_roundtrip() {
    std::env::set_var("INTERENV_ALLOW_MACOS_SOFTWARE_FALLBACK", "1");
    let project_id = "test-project-kek-roundtrip-999";
    let master_key = [77u8; 32];

    let store_res = store_key(project_id, &master_key);
    if let Err(ref e) = store_res {
        if e.contains("org.freedesktop.secrets")
            || e.contains("Platform secure storage failure")
            || e.contains("Keyring initialization error")
            || e.contains("Apple Secure Enclave hardware")
            || e.contains("Touch ID is unavailable")
        {
            return;
        }
    }
    assert!(
        store_res.is_ok(),
        "Failed to store key with KEK: {:?}",
        store_res.err()
    );
    let wrapped = store_res.unwrap();
    #[cfg(windows)]
    assert!(
        wrapped.kek_id == "windows-ncrypt-tpm-v2" || wrapped.kek_id == "windows-dpapi-tpm",
        "Unexpected Windows kek_id: {}",
        wrapped.kek_id
    );
    #[cfg(target_os = "macos")]
    assert!(
        wrapped.kek_id == "macos-secure-enclave-v1"
            || wrapped.kek_id == "macos-secure-enclave"
            || wrapped.kek_id == "macos-keychain-kek-v2",
        "Unexpected macOS kek_id: {}",
        wrapped.kek_id
    );
    #[cfg(target_os = "linux")]
    assert!(
        wrapped.kek_id == "linux-tpm2-v1" || wrapped.kek_id.starts_with("interenv-kek-v2-linux"),
        "Unexpected Linux kek_id: {}",
        wrapped.kek_id
    );

    let retrieve_res = retrieve_key(project_id);
    if let Err(ref e) = retrieve_res {
        if e.contains("org.freedesktop.secrets")
            || e.contains("Platform secure storage failure")
            || e.contains("Keyring initialization error")
            || e.contains("Apple Secure Enclave hardware")
            || e.contains("Touch ID is unavailable")
        {
            let _ = delete_key(project_id);
            return;
        }
    }
    assert!(
        retrieve_res.is_ok(),
        "Failed to retrieve key with KEK: {:?}",
        retrieve_res.err()
    );

    let unwrapped = retrieve_res.unwrap();
    assert_eq!(*unwrapped, master_key, "Unwrapped master key mismatch");

    let _ = delete_key(project_id);
}

#[test]
fn test_enclave_kek_idempotent_store() {
    std::env::set_var("INTERENV_ALLOW_MACOS_SOFTWARE_FALLBACK", "1");
    let project_id = "test-project-kek-idempotent-888";
    let master_key = [88u8; 32];

    let store1 = match store_key(project_id, &master_key) {
        Ok(s) => s,
        Err(ref e)
            if e.contains("org.freedesktop.secrets")
                || e.contains("Platform secure storage failure")
                || e.contains("Keyring initialization error")
                || e.contains("Apple Secure Enclave hardware")
                || e.contains("Touch ID is unavailable") =>
        {
            return;
        }
        Err(e) => panic!("Failed to store key with KEK: {}", e),
    };
    let store2 = match store_key(project_id, &master_key) {
        Ok(s) => s,
        Err(ref e)
            if e.contains("org.freedesktop.secrets")
                || e.contains("Platform secure storage failure")
                || e.contains("Keyring initialization error")
                || e.contains("Apple Secure Enclave hardware")
                || e.contains("Touch ID is unavailable") =>
        {
            let _ = delete_key(project_id);
            return;
        }
        Err(e) => panic!("Failed to store key with KEK: {}", e),
    };
    assert_eq!(
        store1.kek_id, store2.kek_id,
        "KEK ID must be stable across multiple stores"
    );

    let retrieved = match retrieve_key(project_id) {
        Ok(r) => r,
        Err(ref e)
            if e.contains("org.freedesktop.secrets")
                || e.contains("Platform secure storage failure")
                || e.contains("Keyring initialization error")
                || e.contains("Apple Secure Enclave hardware")
                || e.contains("Touch ID is unavailable") =>
        {
            let _ = delete_key(project_id);
            return;
        }
        Err(e) => panic!("Failed to retrieve key: {}", e),
    };
    assert_eq!(*retrieved, master_key);
    let _ = delete_key(project_id);
}
