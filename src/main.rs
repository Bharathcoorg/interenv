use clap::Parser;
use colored::*;
use dialoguer::Confirm;
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process;
use tempfile::Builder;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use interenv::cli::{
    Cli, Commands, EditArgs, HookAction, HookArgs, LockArgs, RunArgs, ShowArgs, ShredArgs,
};
use interenv::crypto::cipher::{decrypt_payload, encrypt_payload, CIPHER_XCHACHA20_POLY1305};
use interenv::crypto::kdf::{
    derive_key_from_passphrase, generate_random_key, generate_salt, OWASP_ARGON2_ITERATIONS,
    OWASP_ARGON2_MEM_KIB, OWASP_ARGON2_PARALLELISM,
};
use interenv::enclave::{self, fallback};
use interenv::envfile::lockfile::{InterLock, KeyProviderType, CURRENT_LOCK_VERSION};
use interenv::envfile::parser::{format_dotenv, parse_dotenv};
use interenv::envfile::Secrets;
use interenv::git::hook::{find_git_dir, install_pre_commit_hook, uninstall_pre_commit_hook};
use interenv::runner::execute_with_env;
use interenv::shredder::{shred_file, TempFileGuard};

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Lock(args) => handle_lock(args),
        Commands::Run(args) => handle_run(args),
        Commands::Edit(args) => handle_edit(args),
        Commands::Show(args) => handle_show(args),
        Commands::Status => handle_status(),
        Commands::Doctor => handle_doctor(),
        Commands::Version => handle_version(),
        Commands::Hook(args) => handle_hook(args),
        Commands::Shred(args) => handle_shred(args),
    };

    if let Err(e) = result {
        eprintln!("{} {}", "❌ Error:".bold().red(), e);
        process::exit(1);
    }
}

use interenv::compute_project_id;

fn handle_lock(args: LockArgs) -> Result<(), String> {
    println!(
        "{}",
        "🛡️  InterEnv: Sealing Project Secrets into Hardware Enclave..."
            .bold()
            .cyan()
    );

    if !args.file.exists() {
        return Err(format!(
            "Source file '{}' does not exist. Please create a .env file first.",
            args.file.display()
        ));
    }

    if args.output.exists() && !args.force {
        let overwrite = Confirm::new()
            .with_prompt(format!(
                "Lockfile '{}' already exists. Overwrite?",
                args.output.display()
            ))
            .default(false)
            .interact()
            .map_err(|e| format!("Confirmation error: {}", e))?;
        if !overwrite {
            println!("Operation cancelled.");
            return Ok(());
        }
    }

    let raw_content = fs::read_to_string(&args.file)
        .map_err(|e| format!("Failed to read {}: {}", args.file.display(), e))?;

    let env_map = parse_dotenv(&raw_content);
    if env_map.is_empty() {
        println!(
            "{} No valid environment variables found in {}.",
            "⚠️ ".yellow(),
            args.file.display()
        );
    }

    let cwd = env::current_dir().map_err(|e| format!("Cannot get current directory: {}", e))?;
    let (project_id, project_name) = compute_project_id(&cwd);

    let salt = generate_salt();
    let salt_hex = hex::encode(salt);

    let (master_key, provider) = if args.passphrase {
        let pass = fallback::prompt_or_get_passphrase("Enter passphrase to seal project secrets")?;
        let key = derive_key_from_passphrase(&pass, &salt)?;
        (key, KeyProviderType::Passphrase)
    } else {
        let key = generate_random_key();
        let (provider, final_key) = enclave::store_key(&project_id, &key, false, None, &salt)?;
        (final_key, provider)
    };

    // Serialize EnvMap to JSON wrapped in Zeroizing buffer
    let json_bytes = Zeroizing::new(
        serde_json::to_vec(&env_map).map_err(|e| format!("Serialization error: {}", e))?,
    );

    let payload = encrypt_payload(&json_bytes, &master_key)?;
    let key_names: Vec<String> = env_map.keys().cloned().collect();

    let lock = InterLock::new(
        project_id.clone(),
        project_name,
        provider,
        salt_hex,
        payload,
        key_names.clone(),
    );

    lock.save(&args.output)?;
    println!(
        "{} Cryptographically sealed {} secrets into '{}'",
        "✅".green(),
        key_names.len().to_string().bold().green(),
        args.output.display().to_string().bold()
    );

    if provider == KeyProviderType::HardwareEnclave {
        println!(
            "🔐 Storage: Hardware Enclave / OS Keyring ({})",
            project_id.cyan()
        );
    } else {
        println!("🔑 Storage: OWASP Argon2id Passphrase Shield");
    }

    // Shred plaintext file
    if !args.no_shred {
        println!(
            "{}",
            "🔥 Securely shredding plaintext file from disk (DoD 5220.22-M)...".yellow()
        );
        shred_file(&args.file)?;
        let _ = fs::remove_file(&args.file);
        println!(
            "{} Plaintext '{}' destroyed. Zero secrets remain on disk!",
            "✨".green(),
            args.file.display()
        );
    } else {
        println!(
            "{}",
            "⚠️  WARNING: Plaintext file was kept (--no-shred). Make sure not to commit it!"
                .bold()
                .yellow()
        );
    }

    // Automatically check Git hook
    if let Some(git_dir) = find_git_dir(&cwd) {
        let hook_path = git_dir.join("hooks").join("pre-commit");
        if !hook_path.exists() {
            println!(
                "💡 Tip: Install Git pre-commit leak protection with: {}",
                "interenv hook install".bold().cyan()
            );
        }
    }

    Ok(())
}

fn load_and_decrypt_env(lockfile_path: Option<&Path>) -> Result<(InterLock, Secrets), String> {
    let cwd = env::current_dir().map_err(|e| format!("Cannot get current directory: {}", e))?;

    let path = match lockfile_path {
        Some(p) => p.to_path_buf(),
        None => InterLock::find_lockfile(&cwd).ok_or_else(|| {
            "No .interenv.lock found in current or parent directories. Run 'interenv lock' first."
                .to_string()
        })?,
    };

    let lock = InterLock::load(&path)?;
    let salt = hex::decode(&lock.kdf_salt_hex)
        .map_err(|e| format!("Invalid salt hex in lockfile: {}", e))?;

    let master_key = enclave::retrieve_key(&lock.project_id, lock.key_provider, &salt)?;

    let decrypted_bytes = decrypt_payload(&lock.payload, &master_key, &lock.cipher)?;
    let env_map: std::collections::BTreeMap<String, String> =
        serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| format!("Decrypted data corruption: {}", e))?;

    let secrets = Secrets::from_env_map(&env_map);
    Ok((lock, secrets))
}

fn handle_run(args: RunArgs) -> Result<(), String> {
    if args.command.is_empty() {
        return Err("No command specified. Usage: interenv run <command> [args...]".into());
    }

    let (_lock, secrets) = load_and_decrypt_env(None)?;

    let program = &args.command[0];
    let trailing_args = if args.command.len() > 1 {
        args.command[1..].to_vec()
    } else {
        Vec::new()
    };

    let code = execute_with_env(program, &trailing_args, &secrets)?;
    if code != 0 {
        process::exit(code);
    }

    Ok(())
}

fn handle_show(args: ShowArgs) -> Result<(), String> {
    let (lock, secrets) = load_and_decrypt_env(None)?;

    if args.json {
        let mut map = std::collections::BTreeMap::new();
        for (k, v) in secrets.iter() {
            if args.reveal {
                map.insert(k.clone(), (**v).clone());
            } else {
                map.insert(k.clone(), mask_value(v));
            }
        }
        let json = serde_json::to_string_pretty(&map)
            .map_err(|e| format!("JSON formatting error: {}", e))?;
        println!("{}", json);
        return Ok(());
    }

    println!(
        "{} Project: {} ({} keys)",
        "🛡️ ".cyan(),
        lock.project_name.bold().cyan(),
        secrets.len().to_string().green()
    );

    if args.raw {
        if !args.reveal {
            println!(
                "{}",
                "# Use --reveal to display unmasked secret values".yellow()
            );
        }
        for (k, v) in secrets.iter() {
            if args.reveal {
                println!("{}={}", k, v.as_str());
            } else {
                println!("{}={}", k, mask_value(v));
            }
        }
    } else {
        println!("{:<30} {:<30}", "KEY".bold(), "VALUE".bold());
        println!("{}", "─".repeat(60));
        for (k, v) in secrets.iter() {
            let displayed = if args.reveal {
                (**v).clone()
            } else {
                mask_value(v)
            };
            println!("{:<30} {:<30}", k.cyan(), displayed);
        }
        if !args.reveal {
            println!(
                "\n💡 Pass {} to view unmasked plaintext values.",
                "--reveal".bold().yellow()
            );
        }
    }

    Ok(())
}

fn mask_value(val: &str) -> String {
    let count = val.chars().count();
    if count <= 6 {
        "••••••••".to_string()
    } else {
        let prefix: String = val.chars().take(3).collect();
        let suffix: String = val
            .chars()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("{}••••••••{}", prefix, suffix)
    }
}

fn handle_status() -> Result<(), String> {
    let cwd = env::current_dir().map_err(|e| format!("Cannot get current directory: {}", e))?;
    let lockfile = InterLock::find_lockfile(&cwd);

    println!(
        "{}",
        "══════════════════════════════════════════════════════════════".cyan()
    );
    println!("             🛡️  INTERENV REPOSITORY SECURITY STATUS           ");
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════".cyan()
    );

    match lockfile {
        Some(path) => {
            let lock = InterLock::load(&path)?;
            println!(
                "🔒 Lockfile:       {} ({})",
                "ACTIVE".bold().green(),
                path.display()
            );
            println!("🏷️  Project Name:   {}", lock.project_name.bold());
            println!(
                "🔑 Keys Sealed:    {} variables",
                lock.keys_count.to_string().green()
            );
            println!("🛡️  Key Provider:   {:?}", lock.key_provider);
            println!("🔒 Cipher Engine:  {}", lock.cipher.cyan());
            println!("🕒 Last Updated:   {}", lock.updated_at);
        }
        None => {
            println!(
                "🔒 Lockfile:       {} (Run 'interenv lock' to seal secrets)",
                "NONE FOUND".bold().red()
            );
        }
    }

    // Check for plaintext .env leakage
    let plaintext_env = cwd.join(".env");
    if plaintext_env.exists() {
        println!(
            "⚠️  Plaintext .env: {} (POTENTIAL LEAK RISK - run 'interenv lock')",
            "EXISTS ON DISK".bold().red()
        );
    } else {
        println!(
            "✨ Plaintext .env: {} (Zero plaintext on disk)",
            "CLEAN".bold().green()
        );
    }

    // Check Git hook
    if let Some(git_dir) = find_git_dir(&cwd) {
        let hook_path = git_dir.join("hooks").join("pre-commit");
        if hook_path.exists() {
            println!(
                "🛡️  Git Hook:       {} (Blocks accidental secret commits)",
                "INSTALLED".bold().green()
            );
        } else {
            println!(
                "🛡️  Git Hook:       {} (Run 'interenv hook install')",
                "NOT INSTALLED".bold().yellow()
            );
        }
    }

    println!(
        "{}",
        "══════════════════════════════════════════════════════════════".cyan()
    );
    Ok(())
}

fn handle_version() -> Result<(), String> {
    println!(
        "interenv v0.1.0 (lockfile schema v{})",
        CURRENT_LOCK_VERSION
    );
    println!("Cipher: XChaCha20-Poly1305 (24-byte random nonces)");
    println!(
        "KDF: Argon2id ({} MiB, {} iters, p={})",
        OWASP_ARGON2_MEM_KIB / 1024,
        OWASP_ARGON2_ITERATIONS,
        OWASP_ARGON2_PARALLELISM
    );
    println!(
        "Hardware Enclave: Windows Credential Manager / macOS Keychain / Linux Secret Service"
    );
    Ok(())
}

fn handle_doctor() -> Result<(), String> {
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════".cyan()
    );
    println!("                  🩺 INTERENV DIAGNOSTIC DOCTOR                ");
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════".cyan()
    );

    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    println!("💻 OS & Architecture: {} ({})", os.green(), arch);

    #[cfg(windows)]
    println!("🔐 Keyring Backend:   Windows Credential Manager / DPAPI");
    #[cfg(target_os = "macos")]
    println!("🔐 Keyring Backend:   Apple Keychain / Secure Enclave (TouchID)");
    #[cfg(target_os = "linux")]
    println!("🔐 Keyring Backend:   FreeDesktop Secret Service / DBus");

    println!(
        "🛡️  KDF Parameters:    Argon2id (m={} MiB, t={}, p={})",
        OWASP_ARGON2_MEM_KIB / 1024,
        OWASP_ARGON2_ITERATIONS,
        OWASP_ARGON2_PARALLELISM
    );
    println!("⚡ Cipher Algorithm:  XChaCha20-Poly1305 (AEAD)");

    println!("\n📁 Storage & File System Advisory:");
    if cfg!(target_os = "macos") {
        println!("⚠️  macOS typically uses APFS (Copy-on-Write). While DoD 3-pass overwrite destroys sector data, APFS/SSDs may allocate new flash blocks. Ensure FileVault is enabled.");
    } else if cfg!(windows) {
        println!("ℹ️  Windows NTFS in-place overwrite active. Ensure BitLocker full-disk encryption is active on flash SSDs.");
    } else {
        println!("ℹ️  Linux ext4 in-place overwrite active. On Btrfs/ZFS, ensure subvolume CoW is taken into account or LUKS is active.");
    }

    println!(
        "{}",
        "══════════════════════════════════════════════════════════════".cyan()
    );
    Ok(())
}

#[cfg(windows)]
fn harden_windows_acl(path: &Path) {
    if let Ok(user) = env::var("USERNAME") {
        let _ = process::Command::new("icacls")
            .arg(path)
            .arg("/inheritance:r")
            .arg(format!("/grant:r:{}:(R,W)", user))
            .output();
    }
}

#[cfg(not(windows))]
fn harden_windows_acl(_path: &Path) {}

fn handle_edit(args: EditArgs) -> Result<(), String> {
    let cwd = env::current_dir().map_err(|e| format!("Cannot get current directory: {}", e))?;
    let lock_path = match args.lockfile {
        Some(p) => p,
        None => InterLock::find_lockfile(&cwd)
            .ok_or_else(|| "No .interenv.lock found. Run 'interenv lock' first.".to_string())?,
    };

    let (mut lock, secrets) = load_and_decrypt_env(Some(&lock_path))?;
    let env_map = secrets.to_env_map();
    let dotenv_str = format_dotenv(&env_map);

    // Create an ephemeral temporary file in the OS secure temp dir (NOT in project cwd)
    let temp_dir = std::env::temp_dir();
    let mut temp_builder = Builder::new();
    temp_builder.prefix(".interenv-edit-").suffix(".env");

    let mut temp_file = temp_builder
        .tempfile_in(&temp_dir)
        .map_err(|e| format!("Failed to create secure temporary file: {}", e))?;

    #[cfg(unix)]
    {
        let mut perms = temp_file
            .as_file()
            .metadata()
            .map_err(|e| format!("Failed to read metadata: {}", e))?
            .permissions();
        perms.set_mode(0o600);
        let _ = temp_file.as_file().set_permissions(perms);
    }

    let temp_path = temp_file.path().to_path_buf();
    harden_windows_acl(&temp_path);

    temp_file
        .write_all(dotenv_str.as_bytes())
        .map_err(|e| format!("Failed to write to temp file: {}", e))?;

    // Create safety net guard that shreds file on scope exit or panic
    let _guard = TempFileGuard {
        path: temp_path.clone(),
    };

    // Register Ctrl+C handler during editing
    let cleanup_path = temp_path.clone();
    let _ = ctrlc::set_handler(move || {
        let _ = shred_file(&cleanup_path);
        let _ = fs::remove_file(&cleanup_path);
        process::exit(130);
    });

    // Determine editor
    let editor = env::var("EDITOR")
        .or_else(|_| env::var("VISUAL"))
        .unwrap_or_else(|_| {
            if cfg!(windows) {
                "notepad".to_string()
            } else {
                "nano".to_string()
            }
        });

    println!("✏️  Opening temporary buffer with '{}'...", editor.cyan());

    let status = process::Command::new(&editor)
        .arg(&temp_path)
        .status()
        .map_err(|e| format!("Failed to launch editor '{}': {}", editor, e))?;

    if !status.success() {
        return Err("Editor exited with error. Changes were discarded.".into());
    }

    // Read modified contents
    let modified_str = fs::read_to_string(&temp_path)
        .map_err(|e| format!("Failed to read modified file: {}", e))?;

    let new_env_map = parse_dotenv(&modified_str);

    // Refuse to write if modified secrets are empty unless --force is provided
    if new_env_map.is_empty() && !args.force {
        let confirm = Confirm::new()
            .with_prompt(
                "All environment variables were removed. Overwrite lockfile with 0 secrets?",
            )
            .default(false)
            .interact()
            .map_err(|e| format!("Confirmation error: {}", e))?;
        if !confirm {
            println!("Edit cancelled; lockfile left unchanged.");
            return Ok(());
        }
    }

    // Re-encrypt
    let salt = hex::decode(&lock.kdf_salt_hex).map_err(|e| format!("Invalid salt hex: {}", e))?;
    let master_key = enclave::retrieve_key(&lock.project_id, lock.key_provider, &salt)?;

    let json_bytes = Zeroizing::new(
        serde_json::to_vec(&new_env_map).map_err(|e| format!("Serialization error: {}", e))?,
    );
    let new_payload = encrypt_payload(&json_bytes, &master_key)?;

    lock.payload = new_payload;
    lock.cipher = CIPHER_XCHACHA20_POLY1305.to_string();
    lock.version = CURRENT_LOCK_VERSION.to_string();
    lock.keys_count = new_env_map.len();
    lock.key_names = new_env_map.keys().cloned().collect();
    lock.updated_at = chrono::Utc::now().to_rfc3339();

    lock.save(&lock_path)?;
    println!(
        "{} Successfully updated and re-sealed {} secrets in '{}'",
        "✅".green(),
        lock.keys_count.to_string().bold().green(),
        lock_path.display().to_string().bold()
    );

    Ok(())
}

fn handle_hook(args: HookArgs) -> Result<(), String> {
    let cwd = env::current_dir().map_err(|e| format!("Cannot get current directory: {}", e))?;
    let git_dir = find_git_dir(&cwd).ok_or_else(|| {
        "Not inside a Git repository. Run this command inside a Git repository.".to_string()
    })?;

    match args.action {
        HookAction::Install => {
            install_pre_commit_hook(&git_dir)?;
            println!(
                "{} Git pre-commit leak protection hook installed successfully!",
                "🛡️ ".green()
            );
            println!("Accidental commits of .env files will now be automatically blocked.");
        }
        HookAction::Uninstall => {
            uninstall_pre_commit_hook(&git_dir)?;
            println!("{} Git pre-commit hook removed.", "⚠️ ".yellow());
        }
    }

    Ok(())
}

fn handle_shred(args: ShredArgs) -> Result<(), String> {
    if !args.target.exists() {
        return Err(format!(
            "Target file '{}' does not exist.",
            args.target.display()
        ));
    }

    println!(
        "🔥 Securely shredding '{}' (DoD 5220.22-M 3-pass overwrite)...",
        args.target.display()
    );
    shred_file(&args.target)?;
    let _ = fs::remove_file(&args.target);
    println!(
        "{} File destroyed and unlinked from physical storage.",
        "✅".green()
    );
    Ok(())
}
