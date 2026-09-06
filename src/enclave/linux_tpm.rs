//! Linux TPM 2.0 hardware Key Encryption Key (KEK) implementation.

#[cfg(all(target_os = "linux", feature = "tpm"))]
use sha2::{Digest, Sha256};

#[cfg(all(target_os = "linux", feature = "tpm"))]
/// Wrap master key with TPM 2.0 primary key modulus binding.
pub fn wrap_key_tpm2(project_id: &str, master_key: &[u8; 32]) -> Result<(String, Vec<u8>), String> {
    use tss_esapi::constants::tss::TPM2_RH_NULL;
    use tss_esapi::structures::{
        HashAlgorithm, PublicBuilder, SymmetricAlgorithm, SymmetricDefinitionObject,
    };
    use tss_esapi::{Context, TctiNameConf};

    let device = if std::path::Path::new("/dev/tpmrm0").exists() {
        TctiNameConf::Device("/dev/tpmrm0".to_string())
    } else if std::path::Path::new("/dev/tpm0").exists() {
        TctiNameConf::Device("/dev/tpm0".to_string())
    } else {
        return Err("No TPM device found".into());
    };

    let mut ctx =
        Context::new(device).map_err(|e| format!("TPM context creation failed: {:?}", e))?;

    let primary = ctx
        .create_primary(
            TPM2_RH_NULL,
            PublicBuilder::new()
                .with_type(tss_esapi::structures::PublicType::SymmetricAlgorithm(
                    SymmetricDefinitionObject::new(
                        SymmetricAlgorithm::Aes,
                        256,
                        HashAlgorithm::Sha256,
                    ),
                ))
                .with_name_hashing_algorithm(HashAlgorithm::Sha256)
                .build()
                .map_err(|e| format!("Primary build: {:?}", e))?,
        )
        .map_err(|e| format!("create_primary: {:?}", e))?;

    let primary_pubkey = primary.public_area().key_public().public_key();
    let primary_bytes = primary_pubkey.value();
    let mut hasher = Sha256::new();
    hasher.update(&primary_bytes);
    hasher.update(b"interenv-tpm-kek-v1:");
    hasher.update(project_id.as_bytes());
    let mask: [u8; 32] = hasher.finalize().into();

    let mut masked = [0u8; 32];
    for i in 0..32 {
        masked[i] = master_key[i] ^ mask[i];
    }

    Ok(("linux-tpm2-v1".to_string(), masked.to_vec()))
}

#[cfg(all(target_os = "linux", feature = "tpm"))]
/// Unwrap master key with TPM 2.0 primary key modulus binding.
pub fn unwrap_key_tpm2(project_id: &str, wrapped: &[u8]) -> Result<[u8; 32], String> {
    if wrapped.len() != 32 {
        return Err("Stored keyring key is not 32 bytes".into());
    }

    use tss_esapi::constants::tss::TPM2_RH_NULL;
    use tss_esapi::structures::{
        HashAlgorithm, PublicBuilder, SymmetricAlgorithm, SymmetricDefinitionObject,
    };
    use tss_esapi::{Context, TctiNameConf};

    let device = if std::path::Path::new("/dev/tpmrm0").exists() {
        TctiNameConf::Device("/dev/tpmrm0".to_string())
    } else if std::path::Path::new("/dev/tpm0").exists() {
        TctiNameConf::Device("/dev/tpm0".to_string())
    } else {
        return Err("No TPM device found".into());
    };

    let mut ctx =
        Context::new(device).map_err(|e| format!("TPM context creation failed: {:?}", e))?;

    let primary = ctx
        .create_primary(
            TPM2_RH_NULL,
            PublicBuilder::new()
                .with_type(tss_esapi::structures::PublicType::SymmetricAlgorithm(
                    SymmetricDefinitionObject::new(
                        SymmetricAlgorithm::Aes,
                        256,
                        HashAlgorithm::Sha256,
                    ),
                ))
                .with_name_hashing_algorithm(HashAlgorithm::Sha256)
                .build()
                .map_err(|e| format!("Primary build: {:?}", e))?,
        )
        .map_err(|e| format!("create_primary: {:?}", e))?;

    let primary_pubkey = primary.public_area().key_public().public_key();
    let primary_bytes = primary_pubkey.value();
    let mut hasher = Sha256::new();
    hasher.update(&primary_bytes);
    hasher.update(b"interenv-tpm-kek-v1:");
    hasher.update(project_id.as_bytes());
    let mask: [u8; 32] = hasher.finalize().into();

    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = wrapped[i] ^ mask[i];
    }

    Ok(key)
}
