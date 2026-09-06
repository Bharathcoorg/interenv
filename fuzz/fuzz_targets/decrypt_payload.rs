#![no_main]
use interenv::crypto::cipher::{decrypt_payload, EncryptedPayload, CIPHER_XCHACHA20_POLY1305};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 48 {
        return;
    }
    let key = [0u8; 32];
    let payload = EncryptedPayload {
        nonce_hex: hex::encode(&data[..24]),
        ciphertext_hex: hex::encode(&data[24..]),
    };
    let _ = decrypt_payload(&payload, &key, CIPHER_XCHACHA20_POLY1305);
});
