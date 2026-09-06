use std::io::IsTerminal;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::envfile::Secrets;

/// Execute a command in a child process with decrypted secrets injected into memory.
/// Plaintext secrets NEVER touch disk or shell history.
pub fn execute_with_env(program: &str, args: &[String], secrets: &Secrets) -> Result<i32, String> {
    if program.is_empty() {
        return Err("No command specified to run. Example: interenv run npm run dev".into());
    }

    // Windows helper: resolve .cmd or .bat if command exists in that form
    let resolved_program = resolve_executable_path(program);

    let mut cmd = Command::new(&resolved_program);
    cmd.args(args);

    // Close stdin when not connected to a TTY to prevent deadlocks
    if std::io::stdin().is_terminal() {
        cmd.stdin(Stdio::inherit());
    } else {
        cmd.stdin(Stdio::null());
    }
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    // Clean environment: preserve minimal essential OS execution variables,
    // clear all arbitrary ambient variables, and inject secrets
    let mut preserved = std::collections::HashMap::new();
    for (k, v) in std::env::vars() {
        let upper = k.to_ascii_uppercase();
        if upper == "PATH"
            || upper == "SYSTEMROOT"
            || upper == "SYSTEMDRIVE"
            || upper == "TEMP"
            || upper == "TMP"
            || upper == "HOME"
            || upper == "USER"
            || upper == "USERPROFILE"
            || upper == "LOGNAME"
            || upper == "SHELL"
            || upper == "LANG"
            || upper == "LC_ALL"
            || upper == "TERM"
            || upper == "CARGO_HOME"
            || upper == "RUSTUP_HOME"
            || upper == "RUSTUP_TOOLCHAIN"
        {
            preserved.insert(k, v);
        }
    }

    cmd.env_clear();
    for (k, v) in preserved {
        cmd.env(k, v);
    }

    // Inject decrypted environment variables directly into volatile process memory
    for (k, v) in secrets.iter() {
        cmd.env(k, &**v);
    }

    #[cfg(target_os = "linux")]
    // SAFETY: pre_exec runs in forked child before exec; prctl sets parent-death signal,
    // linux_seccomp installs BPF filter without heap allocations, and setsid detaches session.
    unsafe {
        use std::os::unix::process::CommandExt;
        let parent_pid = std::process::id() as libc::pid_t;
        cmd.pre_exec(move || {
            libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0,
                0,
                0,
            );
            if libc::getppid() != parent_pid {
                libc::_exit(1);
            }
            if let Err(e) = crate::runner::linux_seccomp::install() {
                return Err(std::io::Error::other(e));
            }
            libc::setsid();
            Ok(())
        });
    }

    #[cfg(target_os = "macos")]
    // SAFETY: pre_exec runs in forked child before exec; setsid detaches
    // session and macos_sandbox installs sandbox profile.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            if let Err(e) = crate::runner::macos_sandbox::install() {
                return Err(std::io::Error::other(e));
            }
            Ok(())
        });
    }

    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    // SAFETY: pre_exec runs in forked child before exec; setsid detaches session.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }

    let mut child = cmd.spawn().map_err(|e| {
        format!(
            "Failed to launch command '{}': {}. Make sure the executable is in your PATH.",
            program, e
        )
    })?;

    #[cfg(windows)]
    {
        use windows::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
        };

        // SAFETY: Win32 CreateJobObjectW accepts null security attributes.
        let job_res = unsafe { CreateJobObjectW(None, None) };
        match job_res {
            Ok(job) => {
                let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                // SAFETY: SetInformationJobObject is called with valid job handle and matching struct size.
                let set_res = unsafe {
                    SetInformationJobObject(
                        job,
                        JobObjectExtendedLimitInformation,
                        &info as *const _ as _,
                        std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                    )
                };
                if set_res.is_ok() {
                    // SAFETY: OpenProcess queries process handle by valid child id.
                    let process_handle = unsafe {
                        OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, false, child.id())
                    };
                    if let Ok(p_handle) = process_handle {
                        // SAFETY: AssignProcessToJobObject assigns process; CloseHandle releases process handle.
                        let _ = unsafe { AssignProcessToJobObject(job, p_handle) };
                        let _ = unsafe { windows::Win32::Foundation::CloseHandle(p_handle) };
                    }
                }
            }
            Err(_) => {
                #[cfg(feature = "unsafe_mode")]
                if std::env::var("INTERENV_UNSAFE").unwrap_or_default() == "1" {
                    eprintln!("⚠️ WARNING: Secret isolation disabled via unsafe_mode feature — NOT for production use");
                } else {
                    eprintln!("❌ Secret isolation unavailable on this system (Windows Job Object creation failed). Aborting execution.");
                    std::process::exit(75);
                }

                #[cfg(not(feature = "unsafe_mode"))]
                {
                    eprintln!("❌ Secret isolation unavailable on this system (Windows Job Object creation failed). Aborting execution.");
                    std::process::exit(75);
                }
            }
        }
    }

    let child_pid = Arc::new(AtomicU32::new(child.id()));
    let pid_clone = child_pid.clone();

    // Register Ctrl+C handler to forward signal to child process
    let _ = ctrlc::set_handler(move || {
        let pid = pid_clone.load(Ordering::SeqCst);
        if pid != 0 {
            #[cfg(unix)]
            // SAFETY: libc::kill sends SIGINT to valid running child PID.
            unsafe {
                libc::kill(pid as i32, libc::SIGINT);
            }
        }
    });

    let status = child.wait().map_err(|e| format!("Process error: {}", e))?;
    child_pid.store(0, Ordering::SeqCst);

    let exit_code = status.code().unwrap_or(i32::from(!status.success()));
    Ok(exit_code)
}

fn resolve_executable_path(prog: &str) -> String {
    #[cfg(windows)]
    {
        let path = std::path::Path::new(prog);
        let has_ext = path.extension().is_some_and(|ext| {
            ext.eq_ignore_ascii_case("exe")
                || ext.eq_ignore_ascii_case("cmd")
                || ext.eq_ignore_ascii_case("bat")
        });
        if !has_ext {
            // Check if executable exists in PATH with standard priority
            if let Ok(path_var) = std::env::var("PATH") {
                for entry in std::env::split_paths(&path_var) {
                    // Prevent PATH hijacking: only examine absolute paths
                    if !entry.is_absolute() {
                        continue;
                    }
                    let exe_candidate = entry.join(format!("{prog}.exe"));
                    if exe_candidate.is_file() {
                        return exe_candidate.to_string_lossy().to_string();
                    }
                    let cmd_candidate = entry.join(format!("{prog}.cmd"));
                    if cmd_candidate.is_file() {
                        return cmd_candidate.to_string_lossy().to_string();
                    }
                    let bat_candidate = entry.join(format!("{prog}.bat"));
                    if bat_candidate.is_file() {
                        return bat_candidate.to_string_lossy().to_string();
                    }
                }
            }
        }
    }
    prog.to_string()
}
