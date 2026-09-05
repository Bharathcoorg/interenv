use interenv::crypto::cipher::{decrypt_payload, encrypt_payload, CIPHER_XCHACHA20_POLY1305};
use std::collections::HashSet;

#[test]
fn test_cipher_roundtrip_variable_sizes() {
    let key = [0x5au8; 32];
    let sizes = [0, 1, 16, 64, 256, 1024, 4096, 16384, 65536];

    for &size in &sizes {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let payload = encrypt_payload(&plaintext, &key).expect("Encryption failed");

        assert_eq!(
            payload.nonce_hex.len(),
            48,
            "XChaCha20 nonce must be 24 bytes (48 hex chars)"
        );

        let decrypted =
            decrypt_payload(&payload, &key, CIPHER_XCHACHA20_POLY1305).expect("Decryption failed");
        assert_eq!(
            *decrypted, plaintext,
            "Decrypted data mismatch for size {}",
            size
        );
    }
}

#[test]
fn test_nonce_uniqueness_sample() {
    let key = [0x42u8; 32];
    let data = b"sample secret data";
    let mut seen_nonces = HashSet::new();
    let iterations = 10_000;

    for _ in 0..iterations {
        let payload = encrypt_payload(data, &key).expect("Encryption error");
        assert!(
            seen_nonces.insert(payload.nonce_hex),
            "FATAL: Duplicate nonce generated!"
        );
    }
}
