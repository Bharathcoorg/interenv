/// Authenticated XChaCha20-Poly1305 encryption and decryption routines.
pub mod cipher;
/// Argon2id key derivation and CSPRNG key generation.
pub mod kdf;

pub use cipher::{decrypt_payload, encrypt_payload, EncryptedPayload};
pub use kdf::{derive_key_from_passphrase, generate_random_key, generate_salt};
