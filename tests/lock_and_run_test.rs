use std::fs;
use tempfile::TempDir;

use interenv::crypto::cipher::{decrypt_payload, encrypt_payload};
use interenv::crypto::kdf::{derive_key_from_passphrase, generate_salt};
use interenv::envfile::lockfile::{InterLock, KeyProviderType};
use interenv::envfile::parser::{format_dotenv, parse_dotenv, EnvMap};
use interenv::runner::execute_with_env;
use interenv::shredder::shred_file;

#[test]
fn test_full_interenv_lifecycle() {
    let temp_dir = TempDir::new().unwrap();
    let env_path = temp_dir.path().join(".env");
    let lock_path = temp_dir.path().join(".interenv.lock");

    // 1. Create realistic .env file
    let original_content = r#"
OPENAI_API_KEY="sk-proj-test123456789"
DATABASE_URL="postgres://app:secret@db.internal:5432/prod"
STRIPE_WEBHOOK_SECRET='whsec_987654321'
PORT=3000
# Comment to ignore
"#;
    fs::write(&env_path, original_content).unwrap();
    assert!(env_path.exists());

    // 2. Parse dotenv
    let env_map = parse_dotenv(original_content);
    assert_eq!(env_map.len(), 4);
    assert_eq!(env_map.get("OPENAI_API_KEY").unwrap(), "sk-proj-test123456789");
    assert_eq!(env_map.get("PORT").unwrap(), "3000");

    // 3. Encrypt with passphrase mode
    let salt = generate_salt();
    let passphrase = "test-encryption-passphrase-2026";
    let master_key = derive_key_from_passphrase(passphrase, &salt).unwrap();

    let json_bytes = serde_json::to_vec(&env_map).unwrap();
    let payload = encrypt_payload(&json_bytes, &master_key).unwrap();

    let key_names: Vec<String> = env_map.keys().cloned().collect();
    let lock = InterLock::new(
        "test-project-123".to_string(),
        "test-project".to_string(),
        KeyProviderType::Passphrase,
        hex::encode(salt),
        payload,
        key_names,
    );

    lock.save(&lock_path).unwrap();
    assert!(lock_path.exists());

    // 4. Securely shred original plaintext file
    shred_file(&env_path).unwrap();
    assert!(!env_path.exists(), "Plaintext .env must be deleted from disk");

    // 5. Decrypt from lockfile
    let loaded_lock = InterLock::load(&lock_path).unwrap();
    assert_eq!(loaded_lock.project_name, "test-project");
    assert_eq!(loaded_lock.keys_count, 4);

    let loaded_salt = hex::decode(&loaded_lock.kdf_salt_hex).unwrap();
    let recovered_key = derive_key_from_passphrase(passphrase, &loaded_salt).unwrap();
    let decrypted_bytes = decrypt_payload(&loaded_lock.payload, &recovered_key).unwrap();

    let recovered_map: EnvMap = serde_json::from_slice(&decrypted_bytes).unwrap();
    assert_eq!(recovered_map.get("OPENAI_API_KEY").unwrap(), "sk-proj-test123456789");
    assert_eq!(recovered_map.get("STRIPE_WEBHOOK_SECRET").unwrap(), "whsec_987654321");

    // 6. Test in-memory process execution with injected environment variables
    let test_args = vec!["-V".to_string()];
    let exit_code = execute_with_env("cargo", &test_args, &recovered_map).unwrap();
    assert_eq!(exit_code, 0);

    // 7. Format dotenv string test
    let reformatted = format_dotenv(&recovered_map);
    assert!(reformatted.contains("OPENAI_API_KEY=sk-proj-test123456789"));
}
