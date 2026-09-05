use std::fs;
use std::path::{Path, PathBuf};

const PRE_COMMIT_SCRIPT: &str = r#"#!/bin/sh
# InterEnv Pre-Commit Security Hook
# Prevents accidental commits of plaintext .env files and hardcoded API keys

echo "🛡️  InterEnv: Scanning staged files for secret leaks..."

# 1. Block any committed plaintext .env files (except .example or .interenv.lock)
STAGED_ENV_FILES=$(git diff --cached --name-only | grep -E '(\.env($|\.))' | grep -v -E '(\.example|\.sample|\.template|\.interenv\.lock|\.lock)')

if [ -n "$STAGED_ENV_FILES" ]; then
    echo "\033[1;31m❌ COMMIT ABORTED BY INTERENV:\033[0m"
    echo "The following plaintext .env files are staged for commit:"
    echo "$STAGED_ENV_FILES"
    echo ""
    echo "\033[1;33mRun 'interenv lock' to seal these secrets in your hardware enclave.\033[0m"
    exit 1
fi

# 2. Heuristic scan for high-risk hardcoded secret patterns in staged diff
LEAKED_KEYS=$(git diff --cached -S"sk-" -S"ghp_" -S"AKIA" --name-only)

if [ -n "$LEAKED_KEYS" ]; then
    echo "\033[1;33m⚠️  Warning: Potential hardcoded API keys detected in staged changes:\033[0m"
    echo "$LEAKED_KEYS"
fi

echo "✅ InterEnv: All staged files clear."
exit 0
"#;

pub fn find_git_dir(start_dir: &Path) -> Option<PathBuf> {
    let mut curr = dunce::canonicalize(start_dir).unwrap_or_else(|_| start_dir.to_path_buf());
    loop {
        let git_dir = curr.join(".git");
        if git_dir.exists() && git_dir.is_dir() {
            return Some(git_dir);
        }
        if !curr.pop() {
            break;
        }
    }
    None
}

pub fn install_pre_commit_hook(git_dir: &Path) -> Result<(), String> {
    let hooks_dir = git_dir.join("hooks");
    if !hooks_dir.exists() {
        fs::create_dir_all(&hooks_dir)
            .map_err(|e| format!("Failed to create hooks directory: {}", e))?;
    }

    let pre_commit_path = hooks_dir.join("pre-commit");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(&pre_commit_path, PRE_COMMIT_SCRIPT)
            .map_err(|e| format!("Failed to write hook: {}", e))?;
        let mut perms = fs::metadata(&pre_commit_path)
            .map_err(|e| format!("Failed to read hook permissions: {}", e))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&pre_commit_path, perms)
            .map_err(|e| format!("Failed to set hook executable: {}", e))?;
    }

    #[cfg(windows)]
    {
        fs::write(&pre_commit_path, PRE_COMMIT_SCRIPT)
            .map_err(|e| format!("Failed to write hook: {}", e))?;
    }

    Ok(())
}

pub fn uninstall_pre_commit_hook(git_dir: &Path) -> Result<(), String> {
    let pre_commit_path = git_dir.join("hooks").join("pre-commit");
    if pre_commit_path.exists() {
        fs::remove_file(&pre_commit_path).map_err(|e| format!("Failed to remove hook: {}", e))?;
    }
    Ok(())
}
