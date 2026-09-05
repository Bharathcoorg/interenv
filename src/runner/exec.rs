use std::process::{Command, Stdio};

use crate::envfile::parser::EnvMap;

/// Execute a command in a child process with decrypted secrets injected into memory.
/// Plaintext secrets NEVER touch disk or shell history.
pub fn execute_with_env(program: &str, args: &[String], env_vars: &EnvMap) -> Result<i32, String> {
    if program.is_empty() {
        return Err("No command specified to run. Example: interenv run npm run dev".into());
    }

    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    // Inject decrypted environment variables directly into volatile process memory
    for (k, v) in env_vars {
        cmd.env(k, v);
    }

    // Set a marker indicator so tools can detect they are protected by interenv
    cmd.env("INTERENV_PROTECTED", "1");

    let mut child = cmd.spawn().map_err(|e| {
        format!(
            "Failed to launch command '{}': {}. Make sure the executable is in your PATH.",
            program, e
        )
    })?;

    let status = child.wait().map_err(|e| format!("Process error: {}", e))?;

    let exit_code = status
        .code()
        .unwrap_or(if status.success() { 0 } else { 1 });
    Ok(exit_code)
}
