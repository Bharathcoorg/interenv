use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// 12-byte initialization vector / nonce (hex-encoded in JSON)
    pub nonce_hex: String,
    /// Ciphertext with appended 16-byte authentication tag (hex-encoded in JSON)
    pub ciphertext_hex: String,
}

/// Encrypt raw plaintext bytes using AES-256-GCM.
pub fn encrypt_payload(plaintext: &[u8], key: &[u8; 32]) -> Result<EncryptedPayload, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("AES-256-GCM encryption error: {}", e))?;

    Ok(EncryptedPayload {
        nonce_hex: hex::encode(nonce_bytes),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

/// Decrypt ciphertext using AES-256-GCM, returning zeroized plaintext buffer.
pub fn decrypt_payload(
    payload: &EncryptedPayload,
    key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let nonce_bytes =
        hex::decode(&payload.nonce_hex).map_err(|e| format!("Invalid nonce hex: {}", e))?;
    if nonce_bytes.len() != 12 {
        return Err("Nonce must be 12 bytes".into());
    }

    let ciphertext = hex::decode(&payload.ciphertext_hex)
        .map_err(|e| format!("Invalid ciphertext hex: {}", e))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let decrypted = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "Decryption failed: integrity check failed or invalid key".to_string())?;

    Ok(Zeroizing::new(decrypted))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let key = [42u8; 32];
        let secret = b"DATABASE_URL=postgres://user:pass@localhost:5432/db";
        let encrypted = encrypt_payload(secret, &key).unwrap();
        let decrypted = decrypt_payload(&encrypted, &key).unwrap();
        assert_eq!(&*decrypted, secret);
    }

    #[test]
    fn test_tamper_detection() {
        let key = [42u8; 32];
        let secret = b"SECRET=supersecret";
        let mut encrypted = encrypt_payload(secret, &key).unwrap();

        // Corrupt ciphertext
        let mut bytes = hex::decode(&encrypted.ciphertext_hex).unwrap();
        bytes[0] ^= 0xFF;
        encrypted.ciphertext_hex = hex::encode(bytes);

        assert!(decrypt_payload(&encrypted, &key).is_err());
    }
}
