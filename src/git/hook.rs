use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const PRE_COMMIT_SCRIPT: &str = r#"#!/bin/sh
# InterEnv Pre-Commit Security Guard
# Prevents accidental commits of plaintext .env files and hardcoded API keys

echo "🛡️  InterEnv: Scanning staged files and diff content for secret leaks..."

# 1. Block any committed plaintext .env files (null-separated, filter=AM)
# Allows .interenv.lock and example files
LEAK_FILES=$(git diff --cached --name-only -z --diff-filter=AM | tr '\0' '\n' | grep -i -E '(^|/)\.?env($|[^a-zA-Z0-9])' | grep -v -E '(\.example|\.sample|\.template|\.interenv\.lock)$' || true)

if [ -n "$LEAK_FILES" ]; then
    printf "\033[1;31m❌ COMMIT ABORTED BY INTERENV:\033[0m\n"
    printf "The following plaintext environment files are staged for commit:\n"
    printf "%s\n" "$LEAK_FILES"
    printf "\n\033[1;33mRun 'interenv lock' to seal these secrets into your hardware enclave.\033[0m\n"
    exit 1
fi

# 2. Comprehensive pattern scan on DIFF CONTENT
LEAK_REGEX='sk-[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{24,}|rk_live_[A-Za-z0-9]{24,}|ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{82,}|gho_[A-Za-z0-9]{36,}|ghu_[A-Za-z0-9]{36,}|ghs_[A-Za-z0-9]{36,}|ghr_[A-Za-z0-9]{36,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{33}|AIza|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|postgres(ql)?://[^\s:]+:[^\s@]+@|mysql://[^\s:]+:[^\s@]+@|mongodb(\+srv)?://[^\s:]+:[^\s@]+@|npm_[A-Za-z0-9]{36}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'

DIFF_LEAKS=$(git diff --cached -U0 | grep -E "^[+]" | grep -v "^[+][+][+]" | grep -E "$LEAK_REGEX" || true)

if [ -n "$DIFF_LEAKS" ]; then
    printf "\033[1;31m❌ COMMIT ABORTED BY INTERENV:\033[0m\n"
    printf "Hardcoded credentials or API keys detected in staged diff:\n"
    printf "%s\n" "$DIFF_LEAKS"
    printf "\n\033[1;33mPlease remove sensitive tokens or seal them with InterEnv.\033[0m\n"
    exit 1
fi

# 3. Check git submodules recursively if present
if [ -f ".gitmodules" ]; then
    git submodule foreach --quiet --recursive '
        SUB_LEAKS=$(git diff --cached --name-only -z --diff-filter=AM | tr "\0" "\n" | grep -i -E "(^|/)\.?env($|[^a-zA-Z0-9])" | grep -v -E "(\.example|\.sample|\.template|\.interenv\.lock)$" || true)
        if [ -n "$SUB_LEAKS" ]; then
            echo "❌ Secret leak in submodule $name: $SUB_LEAKS"
            exit 1
        fi
    ' || exit 1
fi

echo "✅ InterEnv: Staged files & diff clear."
exit 0
"#;

pub fn find_git_dir(start_dir: &Path) -> Option<PathBuf> {
    // Try resolving via git rev-parse for full submodule / worktree fidelity
    if let Ok(output) = Command::new("git")
        .arg("rev-parse")
        .arg("--git-common-dir")
        .current_dir(start_dir)
        .output()
    {
        if output.status.success() {
            let common_path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let common_path = PathBuf::from(common_path_str);
            let resolved = if common_path.is_absolute() {
                common_path
            } else {
                start_dir.join(common_path)
            };
            if resolved.exists() {
                return Some(resolved);
            }
        }
    }

    // Fallback: directory walking
    let mut curr = dunce::canonicalize(start_dir).unwrap_or_else(|_| start_dir.to_path_buf());
    loop {
        let git_entry = curr.join(".git");
        if git_entry.is_dir() {
            return Some(git_entry);
        } else if git_entry.is_file() {
            if let Ok(content) = fs::read_to_string(&git_entry) {
                if let Some(path_str) = content.strip_prefix("gitdir:") {
                    let p = PathBuf::from(path_str.trim());
                    let resolved = if p.is_absolute() { p } else { curr.join(p) };
                    if resolved.exists() {
                        return Some(resolved);
                    }
                }
            }
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
