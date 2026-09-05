use clap::Parser;
use colored::*;
use dialoguer::Confirm;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process;
use tempfile::Builder;

use interenv::cli::{
    Cli, Commands, EditArgs, HookAction, HookArgs, LockArgs, RunArgs, ShowArgs, ShredArgs,
};
use interenv::crypto::cipher::{decrypt_payload, encrypt_payload};
use interenv::crypto::kdf::{derive_key_from_passphrase, generate_random_key, generate_salt};
use interenv::enclave::{self, fallback};
use interenv::envfile::lockfile::{InterLock, KeyProviderType};
use interenv::envfile::parser::{format_dotenv, parse_dotenv, EnvMap};
use interenv::git::hook::{find_git_dir, install_pre_commit_hook, uninstall_pre_commit_hook};
use interenv::runner::execute_with_env;
use interenv::shredder::shred_file;

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Lock(args) => handle_lock(args),
        Commands::Run(args) => handle_run(args),
        Commands::Edit(args) => handle_edit(args),
        Commands::Show(args) => handle_show(args),
        Commands::Status => handle_status(),
        Commands::Hook(args) => handle_hook(args),
        Commands::Shred(args) => handle_shred(args),
    };

    if let Err(e) = result {
        eprintln!("{} {}", "❌ Error:".bold().red(), e);
        process::exit(1);
    }
}

fn compute_project_id(cwd: &Path) -> (String, String) {
    let canonical = dunce::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let folder_name = canonical
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project")
        .to_string();

    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string_lossy().as_bytes());
    let hash = hex::encode(hasher.finalize());
    let project_id = format!("{}-{}", folder_name, &hash[..12]);
    (project_id, folder_name)
}

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
            "{} No environment variables found in {}.",
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
        let provider = enclave::store_key(&project_id, &key, false, None, &salt)?;
        (key, provider)
    };

    // Serialize EnvMap to JSON for structured encrypted storage
    let json_bytes =
        serde_json::to_vec(&env_map).map_err(|e| format!("Serialization error: {}", e))?;

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
        println!("🔑 Storage: Argon2id Passphrase Shield");
    }

    // Shred plaintext file
    if !args.no_shred {
        println!(
            "{}",
            "🔥 Securely shredding plaintext file from disk (DoD 5220.22-M)...".yellow()
        );
        shred_file(&args.file)?;
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

fn load_and_decrypt_env(lockfile_path: Option<&Path>) -> Result<(InterLock, EnvMap), String> {
    let cwd = env::current_dir().map_err(|e| format!("Cannot get current directory: {}", e))?;

    let path = match lockfile_path {
        Some(p) => p.to_path_buf(),
        None => InterLock::find_lockfile(&cwd).ok_or_else(|| {
            "No .interenv.lock found in current or parent directories. Run 'interenv lock' first.".to_string()
        })?,
    };

    let lock = InterLock::load(&path)?;
    let salt = hex::decode(&lock.kdf_salt_hex)
        .map_err(|e| format!("Invalid salt hex in lockfile: {}", e))?;

    let master_key = enclave::retrieve_key(&lock.project_id, lock.key_provider, &salt)?;

    let decrypted_bytes = decrypt_payload(&lock.payload, &master_key)?;
    let env_map: EnvMap = serde_json::from_slice(&decrypted_bytes)
        .map_err(|e| format!("Decrypted data corruption: {}", e))?;

    Ok((lock, env_map))
}

fn handle_run(args: RunArgs) -> Result<(), String> {
    if args.command.is_empty() {
        return Err("No command specified. Usage: interenv run <command> [args...]".into());
    }

    let (_lock, env_map) = load_and_decrypt_env(None)?;

    let program = &args.command[0];
    let trailing_args = if args.command.len() > 1 {
        args.command[1..].to_vec()
    } else {
        Vec::new()
    };

    let code = execute_with_env(program, &trailing_args, &env_map)?;
    if code != 0 {
        process::exit(code);
    }

    Ok(())
}

fn handle_show(args: ShowArgs) -> Result<(), String> {
    let (lock, env_map) = load_and_decrypt_env(None)?;

    println!(
        "{} Project: {} ({} keys)",
        "🛡️ ".cyan(),
        lock.project_name.bold().cyan(),
        env_map.len().to_string().green()
    );

    if args.raw {
        if !args.reveal {
            println!(
                "{}",
                "# Use --reveal to display unmasked secret values".yellow()
            );
        }
        for (k, v) in &env_map {
            if args.reveal {
                println!("{}={}", k, v);
            } else {
                println!("{}={}", k, mask_value(v));
            }
        }
    } else {
        println!("{:<30} {:<30}", "KEY".bold(), "VALUE".bold());
        println!("{}", "─".repeat(60));
        for (k, v) in &env_map {
            let displayed = if args.reveal {
                v.clone()
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
    if val.len() <= 6 {
        "••••••••".to_string()
    } else {
        let prefix = &val[..3];
        let suffix = &val[val.len() - 3..];
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

fn handle_edit(args: EditArgs) -> Result<(), String> {
    let cwd = env::current_dir().map_err(|e| format!("Cannot get current directory: {}", e))?;
    let lock_path = match args.lockfile {
        Some(p) => p,
        None => InterLock::find_lockfile(&cwd)
            .ok_or_else(|| "No .interenv.lock found. Run 'interenv lock' first.".to_string())?,
    };

    let (mut lock, env_map) = load_and_decrypt_env(Some(&lock_path))?;
    let dotenv_str = format_dotenv(&env_map);

    // Create an ephemeral temporary file for editor
    let mut temp_file = Builder::new()
        .prefix(".interenv-edit-")
        .suffix(".env")
        .tempfile_in(&cwd)
        .map_err(|e| format!("Failed to create secure temporary file: {}", e))?;

    temp_file
        .write_all(dotenv_str.as_bytes())
        .map_err(|e| format!("Failed to write to temp file: {}", e))?;

    let temp_path = temp_file.path().to_path_buf();

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
        let _ = shred_file(&temp_path);
        return Err("Editor exited with error. Changes were discarded.".into());
    }

    // Read modified contents
    let modified_str = fs::read_to_string(&temp_path)
        .map_err(|e| format!("Failed to read modified file: {}", e))?;

    // Shred temporary buffer immediately
    shred_file(&temp_path)?;

    let new_env_map = parse_dotenv(&modified_str);

    // Re-encrypt
    let salt = hex::decode(&lock.kdf_salt_hex).map_err(|e| format!("Invalid salt hex: {}", e))?;
    let master_key = enclave::retrieve_key(&lock.project_id, lock.key_provider, &salt)?;

    let json_bytes =
        serde_json::to_vec(&new_env_map).map_err(|e| format!("Serialization error: {}", e))?;
    let new_payload = encrypt_payload(&json_bytes, &master_key)?;

    lock.payload = new_payload;
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
    println!(
        "{} File destroyed and unlinked from physical storage.",
        "✅".green()
    );
    Ok(())
}
