use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Identifier for the authenticated XChaCha20-Poly1305 cipher.
pub const CIPHER_XCHACHA20_POLY1305: &str = "xchacha20-poly1305";

/// Serialized payload container storing nonce and ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedPayload {
    /// Nonce for cipher (24 bytes for XChaCha20, hex-encoded)
    pub nonce_hex: String,
    /// Ciphertext with appended 16-byte Poly1305 authentication tag (hex-encoded)
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

/// Decrypt ciphertext using XChaCha20-Poly1305, returning zeroized plaintext buffer.
pub fn decrypt_payload(
    payload: &EncryptedPayload,
    key: &[u8; 32],
    cipher_name: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if cipher_name != CIPHER_XCHACHA20_POLY1305 {
        return Err(format!(
            "Unsupported cipher: {}. InterEnv v1.0 requires xchacha20-poly1305. Re-lock secrets using 'interenv lock --force'.",
            cipher_name
        ));
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
}
