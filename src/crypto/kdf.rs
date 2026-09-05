use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

/// Generate 32 bytes of cryptographically secure random bytes for a master key.
pub fn generate_random_key() -> Zeroizing<[u8; 32]> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    Zeroizing::new(key)
}

/// Generate a 16-byte random salt for key derivation.
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive a 32-byte master key from a user passphrase and salt using Argon2id.
pub fn derive_key_from_passphrase(
    passphrase: &str,
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let params = Params::new(64 * 1024, 3, 4, Some(32))
        .map_err(|e| format!("Argon2 params error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Argon2 derivation error: {}", e))?;

    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_key() {
        let k1 = generate_random_key();
        let k2 = generate_random_key();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn test_kdf_consistency() {
        let salt = generate_salt();
        let pass = "super-secret-passphrase";
        let k1 = derive_key_from_passphrase(pass, &salt).unwrap();
        let k2 = derive_key_from_passphrase(pass, &salt).unwrap();
        assert_eq!(*k1, *k2);
    }
}
