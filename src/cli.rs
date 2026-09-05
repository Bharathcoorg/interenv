use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "interenv",
    author = "Bharath B R <bharathcoorg7@gmail.com>",
    version = "0.1.0",
    about = "🛡️  Hardware-Enclave Protected Secrets for Terminal & Git (Zero Plaintext .env on Disk) by Interlayer",
    long_about = "InterEnv eliminates plaintext secrets from developer machines. It encrypts project .env files directly into your OS Hardware Security Enclave (TouchID, TPM 2.0, Windows Hello) and injects decrypted secrets directly into volatile process memory at runtime."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// 🔒 Seal an existing .env file into the hardware enclave and securely shred the plaintext
    Lock(LockArgs),

    /// ⚡ Run a command with decrypted secrets injected into memory (never touches disk)
    Run(RunArgs),

    /// ✏️  Edit project secrets securely in your default editor and re-seal automatically
    Edit(EditArgs),

    /// 👁️  Display project secrets (redacted by default for security)
    Show(ShowArgs),

    /// 📊 Inspect repository security status and hardware enclave binding
    Status,

    /// 🩺 Diagnostic doctor to inspect platform hardware enclave, KDF, cipher, and filesystem CoW shred safety
    Doctor,

    /// ℹ️  Display current InterEnv version and cryptographic engine specs
    Version,

    /// 🛡️  Manage Git pre-commit hooks to prevent accidental plaintext leaks
    Hook(HookArgs),

    /// 💥 Cryptographically shred and erase a sensitive plaintext file from disk
    Shred(ShredArgs),
}

#[derive(Args, Debug)]
pub struct LockArgs {
    /// Path to the plaintext environment file to seal (defaults to .env)
    #[arg(short, long, default_value = ".env")]
    pub file: PathBuf,

    /// Output lockfile path (defaults to .interenv.lock)
    #[arg(short, long, default_value = ".interenv.lock")]
    pub output: PathBuf,

    /// Use a password/passphrase instead of hardware enclave (recommended for CI/CD or Docker)
    #[arg(long)]
    pub passphrase: bool,

    /// Keep the plaintext file instead of securely shredding it (NOT RECOMMENDED)
    #[arg(long)]
    pub no_shred: bool,

    /// Force overwrite if lockfile already exists
    #[arg(short, long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// The command to execute with vaulted secrets in memory
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Args, Debug)]
pub struct EditArgs {
    /// Path to the lockfile (defaults to searching current and parent directories)
    #[arg(short, long)]
    pub lockfile: Option<PathBuf>,

    /// Allow saving even if all environment variables were emptied
    #[arg(short, long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct ShowArgs {
    /// Unmask and display raw plaintext values on screen
    #[arg(long)]
    pub reveal: bool,

    /// Output in standard .env format instead of formatted table
    #[arg(long)]
    pub raw: bool,

    /// Output clean JSON format (ideal for programmatic wrappers and Node.js SDK)
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct HookArgs {
    #[command(subcommand)]
    pub action: HookAction,
}

#[derive(Subcommand, Debug)]
pub enum HookAction {
    /// Install pre-commit security hook in .git/hooks
    Install,
    /// Remove pre-commit security hook
    Uninstall,
}

#[derive(Args, Debug)]
pub struct ShredArgs {
    /// Path of the file to securely shred with DoD 5220.22-M 3-pass overwrite
    pub target: PathBuf,
}
