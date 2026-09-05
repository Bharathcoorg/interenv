#[cfg(target_os = "linux")]
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;

#[cfg(target_os = "linux")]
pub fn install() -> Result<(), String> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let deny_syscalls = [
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kcmp,
        libc::SYS_unshare,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_setns,
        libc::SYS_finit_module,
        libc::SYS_init_module,
        libc::SYS_delete_module,
        libc::SYS_personality,
        libc::SYS_acct,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_bpf,
    ];

    for syscall in deny_syscalls {
        if let Ok(rule) = SeccompRule::new(vec![]) {
            rules.insert(syscall, vec![rule]);
        }
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(1),
        SeccompAction::Allow,
        target_arch(),
    )
    .map_err(|e| format!("Seccomp filter init failed: {}", e))?;

    let bpf: BpfProgram = filter
        .try_into()
        .map_err(|e| format!("BPF compile failed: {}", e))?;

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
