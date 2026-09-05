use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const CIPHER_XCHACHA20_POLY1305: &str = "xchacha20-poly1305";
pub const CIPHER_AES_256_GCM_LEGACY: &str = "aes-256-gcm";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedPayload {
    /// Nonce for cipher (24 bytes for XChaCha20, 12 bytes for legacy AES-GCM, hex-encoded)
    pub nonce_hex: String,
    /// Ciphertext with appended authentication tag (hex-encoded)
    pub ciphertext_hex: String,
}

/// Encrypt raw plaintext bytes using XChaCha20-Poly1305 with a 24-byte random nonce.
pub fn encrypt_payload(plaintext: &[u8], key: &[u8; 32]) -> Result<EncryptedPayload, String> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));

    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("XChaCha20-Poly1305 encryption error: {}", e))?;

    Ok(EncryptedPayload {
        nonce_hex: hex::encode(nonce_bytes),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

/// Decrypt ciphertext using XChaCha20-Poly1305 or legacy AES-256-GCM, returning zeroized plaintext buffer.
pub fn decrypt_payload(
    payload: &EncryptedPayload,
    key: &[u8; 32],
    cipher_name: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if cipher_name == CIPHER_AES_256_GCM_LEGACY {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| format!("AES-256-GCM key initialization error: {}", e))?;
        let nonce_bytes =
            hex::decode(&payload.nonce_hex).map_err(|e| format!("Invalid nonce hex: {}", e))?;
        if nonce_bytes.len() != 12 {
            return Err(format!(
                "Invalid nonce length: expected 12 bytes for AES-256-GCM, got {}",
                nonce_bytes.len()
            ));
        }
        let ciphertext = hex::decode(&payload.ciphertext_hex)
            .map_err(|e| format!("Invalid ciphertext hex: {}", e))?;
        let nonce = AesNonce::from_slice(&nonce_bytes);
        let decrypted = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| "Decryption failed: integrity check failed or invalid key".to_string())?;
        return Ok(Zeroizing::new(decrypted));
    }

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));

    let nonce_bytes =
        hex::decode(&payload.nonce_hex).map_err(|e| format!("Invalid nonce hex: {}", e))?;
    if nonce_bytes.len() != 24 {
        return Err(format!(
            "Invalid nonce length: expected 24 bytes for XChaCha20, got {}",
            nonce_bytes.len()
        ));
    }

    let ciphertext = hex::decode(&payload.ciphertext_hex)
        .map_err(|e| format!("Invalid ciphertext hex: {}", e))?;

    let nonce = XNonce::from_slice(&nonce_bytes);
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
        assert_eq!(encrypted.nonce_hex.len(), 48); // 24 bytes * 2
        let decrypted = decrypt_payload(&encrypted, &key, CIPHER_XCHACHA20_POLY1305).unwrap();
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

        assert!(decrypt_payload(&encrypted, &key, CIPHER_XCHACHA20_POLY1305).is_err());
    }

    #[test]
    fn test_legacy_aes_gcm_decrypt() {
        let key = [99u8; 32];
        let secret = b"LEGACY_KEY=supersecret123";
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_bytes = [7u8; 12];
        let nonce = AesNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, secret.as_ref()).unwrap();

        let payload = EncryptedPayload {
            nonce_hex: hex::encode(nonce_bytes),
            ciphertext_hex: hex::encode(ciphertext),
        };

        let decrypted = decrypt_payload(&payload, &key, CIPHER_AES_256_GCM_LEGACY).unwrap();
        assert_eq!(&*decrypted, secret);
    }
}
