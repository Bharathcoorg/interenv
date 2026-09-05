use interenv::enclave::keyring_backend::{delete_key, retrieve_key, store_key};

#[test]
fn test_enclave_kek_roundtrip() {
    let project_id = "test-project-kek-roundtrip-999";
    let master_key = [77u8; 32];

    let store_res = store_key(project_id, &master_key);
    assert!(
        store_res.is_ok(),
        "Failed to store key with KEK: {:?}",
        store_res.err()
    );

    let retrieve_res = retrieve_key(project_id);
    assert!(
        retrieve_res.is_ok(),
        "Failed to retrieve key with KEK: {:?}",
        retrieve_res.err()
    );

    let unwrapped = retrieve_res.unwrap();
    assert_eq!(*unwrapped, master_key, "Unwrapped master key mismatch");

    let _ = delete_key(project_id);
}
