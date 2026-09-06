/// Process execution engine and environment injection.
pub mod exec;
/// Linux seccomp BPF isolation.
#[cfg(target_os = "linux")]
pub mod linux_seccomp;
/// macOS sandbox profile isolation.
#[cfg(target_os = "macos")]
pub mod macos_sandbox;

pub use exec::execute_with_env;
