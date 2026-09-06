#[cfg(target_os = "linux")]
use seccompiler::{BpfProgram, SeccompAction};
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;

/// Build the seccomp BPF filter that denies ptrace and memory-inspection syscalls.
///
/// The deny-list is expressed as `syscall -> vec![]` (an empty vector of rules).
/// Per seccompiler's contract, `SeccompRule::new(vec![])` is rejected with
/// `Error::EmptyRule`, so a rule with no conditions is represented by an empty
/// `Vec<SeccompRule>`, which matches the syscall number regardless of arguments.
/// Inserting `vec![SeccompRule::new(vec![])]` instead silently inserts nothing and
/// the deny-list silently becomes a no-op — a real defect that this function
/// guards against (see the `deny_list_is_non_empty` test).
#[cfg(target_os = "linux")]
pub fn build_filter() -> Result<BpfProgram, String> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let deny_syscalls = [
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kcmp,
        libc::SYS_unshare,
    ];

    for syscall in deny_syscalls {
        rules.insert(syscall, vec![]);
    }

    SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(1),
        target_arch(),
    )
    .map_err(|e| format!("Seccomp filter init failed: {}", e))?
    .try_into()
    .map_err(|e| format!("BPF compile failed: {}", e))
}

/// Install the Linux seccomp BPF filter denying ptrace and memory inspection.
#[cfg(target_os = "linux")]
pub fn install() -> Result<(), String> {
    let bpf: BpfProgram = build_filter()?;

    // SAFETY: prctl is called with PR_SET_NO_NEW_PRIVS and 1 to prevent
    // child processes from gaining elevated privileges via setuid binaries.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(format!(
            "PR_SET_NO_NEW_PRIVS failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    if let Err(e) = seccompiler::apply_filter(&bpf) {
        return Err(format!("apply_filter failed: {}", e));
    }

    Ok(())
}

/// Detect the target architecture for seccomp BPF compilation.
#[cfg(target_os = "linux")]
pub fn target_arch() -> seccompiler::TargetArch {
    #[cfg(target_arch = "x86_64")]
    {
        seccompiler::TargetArch::x86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        seccompiler::TargetArch::aarch64
    }
    #[cfg(target_arch = "arm")]
    {
        seccompiler::TargetArch::arm
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
    {
        seccompiler::TargetArch::x86_64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test: the deny-list must actually map each protected syscall
    /// to a non-empty rule chain. A previous implementation inserted
    /// `vec![SeccompRule::new(vec![])]`, which seccompiler rejects with
    /// `Error::EmptyRule`, so the `if let Ok(rule)` branch was dead and none of
    /// the listed syscalls were ever denied.
    #[test]
    fn deny_list_is_non_empty() {
        let bpf = build_filter().expect("filter must compile");
        // The compiled BPF program must be larger than the bare arch-validation
        // + mismatch-action sequence; otherwise no deny rules made it in.
        assert!(
            bpf.len() > 2,
            "BPF program too small ({}); deny-list appears empty",
            bpf.len()
        );
    }
}