use interenv::crypto::cipher::{decrypt_payload, encrypt_payload, CIPHER_XCHACHA20_POLY1305};
use proptest::prelude::*;
use std::collections::HashSet;

proptest! {
    #[test]
    fn cipher_roundtrip_arbitrary_size(plaintext in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let enc = encrypt_payload(&plaintext, &key).unwrap();
        let dec = decrypt_payload(&enc, &key, CIPHER_XCHACHA20_POLY1305).unwrap();
        prop_assert_eq!(&*dec, &plaintext[..]);
    }

    #[test]
    fn cipher_tamper_detection(n in 0usize..100) {
        let key = [7u8; 32];
        let plaintext = vec![0xABu8; 64];
        let mut enc = encrypt_payload(&plaintext, &key).unwrap();
        let mut bytes = hex::decode(&enc.ciphertext_hex).unwrap();
        let idx = n % bytes.len();
        bytes[idx] ^= 0xFF;
        enc.ciphertext_hex = hex::encode(bytes);
        prop_assert!(decrypt_payload(&enc, &key, CIPHER_XCHACHA20_POLY1305).is_err());
    }

    #[test]
    fn cipher_tamper_nonce(n in 0usize..24) {
        let key = [7u8; 32];
        let plaintext = vec![0xABu8; 64];
        let mut enc = encrypt_payload(&plaintext, &key).unwrap();
        let mut bytes = hex::decode(&enc.nonce_hex).unwrap();
        let idx = n % bytes.len();
        bytes[idx] ^= 0xFF;
        enc.nonce_hex = hex::encode(bytes);
        prop_assert!(decrypt_payload(&enc, &key, CIPHER_XCHACHA20_POLY1305).is_err());
    }
}

#[test]
fn nonce_collision_resistance() {
    let key = [1u8; 32];
    let mut seen = HashSet::new();
    for _ in 0..50_000 {
        let enc = encrypt_payload(b"x", &key).unwrap();
        assert!(
            seen.insert(enc.nonce_hex),
            "Nonce collision in 50k iterations!"
        );
    }
}
