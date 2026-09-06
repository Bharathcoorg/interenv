//! Linux TPM 2.0 hardware Key Encryption Key (KEK) implementation.

#[cfg(all(target_os = "linux", feature = "tpm"))]
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        Digest, KeyedHashScheme, PublicBuilder, PublicKeyedHashParameters, RsaExponent,
        SensitiveData, SymmetricDefinitionObject,
    },
    tcti_ldr::{DeviceConfig, TctiNameConf},
    traits::{Marshall, UnMarshall},
    Context,
};

#[cfg(all(target_os = "linux", feature = "tpm"))]
#[derive(serde::Serialize, serde::Deserialize)]
struct TpmSealedBlob {
    private: String,
    public: String,
}

#[cfg(all(target_os = "linux", feature = "tpm"))]
fn open_tpm_context() -> Result<Context, String> {
    let device_path = if std::path::Path::new("/dev/tpmrm0").exists() {
        "/dev/tpmrm0"
    } else if std::path::Path::new("/dev/tpm0").exists() {
        "/dev/tpm0"
    } else {
        return Err("No TPM device found (/dev/tpmrm0 or /dev/tpm0)".into());
    };

    let conf = TctiNameConf::Device(DeviceConfig {
        path: std::path::PathBuf::from(device_path),
    });

    Context::new(conf).map_err(|e| format!("TPM context creation failed: {:?}", e))
}

#[cfg(all(target_os = "linux", feature = "tpm"))]
/// Wrap master key with TPM 2.0 primary key modulus binding.
pub fn wrap_key_tpm2(
    _project_id: &str,
    master_key: &[u8; 32],
) -> Result<(String, Vec<u8>), String> {
    let mut ctx = open_tpm_context()?;

    // 1. Create primary storage key (RSA 2048)
    let primary_public = tss_esapi::utils::create_restricted_decryption_rsa_public(
        SymmetricDefinitionObject::AES_128_CFB,
        RsaKeyBits::Rsa2048,
        RsaExponent::default(),
    )
    .map_err(|e| format!("Primary public template build failed: {:?}", e))?;

    let primary = ctx
        .create_primary(Hierarchy::Owner, primary_public, None, None, None, None)
        .map_err(|e| format!("TPM create_primary failed: {:?}", e))?;

    // 2. Create a child KeyedHash key with sensitive_data = master_key (32 bytes)
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        .build()
        .map_err(|e| format!("ObjectAttributes build failed: {:?}", e))?;

    let sealed_public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(|e| format!("Sealed public build failed: {:?}", e))?;

    let sensitive_data = SensitiveData::try_from(master_key.to_vec())
        .map_err(|e| format!("SensitiveData creation failed: {:?}", e))?;

    let create_result = ctx
        .create(
            primary.key_handle,
            sealed_public,
            None,
            Some(sensitive_data),
            None,
            None,
        )
        .map_err(|e| format!("TPM create (seal) failed: {:?}", e))?;

    // 3. Serialize the sealed private + public blobs for storage
    let priv_bytes = create_result.out_private.value();
    let pub_bytes = create_result
        .out_public
        .marshall()
        .map_err(|e| format!("Marshalling public area failed: {:?}", e))?;

    let blob = TpmSealedBlob {
        private: hex::encode(priv_bytes),
        public: hex::encode(pub_bytes),
    };

    let serialized = serde_json::to_vec(&blob)
        .map_err(|e| format!("JSON serialization of sealed blobs failed: {:?}", e))?;

    Ok(("linux-tpm2-v2".to_string(), serialized))
}

#[cfg(all(target_os = "linux", feature = "tpm"))]
/// Unwrap master key with TPM 2.0 primary key modulus binding.
pub fn unwrap_key_tpm2(_project_id: &str, wrapped: &[u8]) -> Result<[u8; 32], String> {
    let blob: TpmSealedBlob = serde_json::from_slice(wrapped)
        .map_err(|e| format!("Failed to parse sealed TPM blob: {:?}", e))?;

    let priv_bytes = hex::decode(&blob.private)
        .map_err(|e| format!("Failed to decode private blob hex: {:?}", e))?;
    let pub_bytes = hex::decode(&blob.public)
        .map_err(|e| format!("Failed to decode public blob hex: {:?}", e))?;

    let priv_obj = tss_esapi::structures::Private::try_from(priv_bytes)
        .map_err(|e| format!("Failed to unmarshal private blob: {:?}", e))?;
    let pub_obj = tss_esapi::structures::Public::unmarshall(&pub_bytes)
        .map_err(|e| format!("Failed to unmarshal public blob: {:?}", e))?;

    let mut ctx = open_tpm_context()?;

    // 1. Recreate primary storage key
    let primary_public = tss_esapi::utils::create_restricted_decryption_rsa_public(
        SymmetricDefinitionObject::AES_128_CFB,
        RsaKeyBits::Rsa2048,
        RsaExponent::default(),
    )
    .map_err(|e| format!("Primary public template build failed: {:?}", e))?;

    let primary = ctx
        .create_primary(Hierarchy::Owner, primary_public, None, None, None, None)
        .map_err(|e| format!("TPM create_primary failed: {:?}", e))?;

    // 2. Load the sealed key
    let key_handle = ctx
        .load(primary.key_handle, priv_obj, pub_obj)
        .map_err(|e| format!("TPM load failed: {:?}", e))?;

    // 3. Unseal the 32-byte master key
    let unsealed = ctx
        .unseal(key_handle.into())
        .map_err(|e| format!("TPM unseal failed: {:?}", e))?;

    let unsealed_bytes = unsealed.value();
    if unsealed_bytes.len() != 32 {
        return Err(format!(
            "Unsealed key size invalid: expected 32 bytes, got {}",
            unsealed_bytes.len()
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(unsealed_bytes);
    Ok(key)
}
