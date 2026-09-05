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
    if atty::is(atty::Stream::Stdin) {
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

    // Set a marker indicator so tools can detect they are protected by interenv
    cmd.env("INTERENV_PROTECTED", "1");

    #[cfg(target_os = "linux")]
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            if let Err(e) = crate::runner::linux_seccomp::install() {
                std::env::set_var("INTERENV_SECCOMP_FAILED", &e);
                return Err(std::io::Error::other(e));
            }
            Ok(())
        });
    }

    #[cfg(target_os = "macos")]
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            if let Err(e) = crate::runner::macos_sandbox::install() {
                std::env::set_var("INTERENV_SANDBOX_FAILED", &e);
                return Err(std::io::Error::other(e));
            }
            Ok(())
        });
    }

    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
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

        let job_res = unsafe { CreateJobObjectW(None, None) };
        match job_res {
            Ok(job) => {
                let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let set_res = unsafe {
                    SetInformationJobObject(
                        job,
                        JobObjectExtendedLimitInformation,
                        &info as *const _ as _,
                        std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                    )
                };
                if set_res.is_ok() {
                    let process_handle = unsafe {
                        OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, false, child.id())
                    };
                    if let Ok(p_handle) = process_handle {
                        let _ = unsafe { AssignProcessToJobObject(job, p_handle) };
                        let _ = unsafe { windows::Win32::Foundation::CloseHandle(p_handle) };
                    }
                }
            }
            Err(_) => {
                if std::env::var("INTERENV_UNSAFE").unwrap_or_default() != "1" {
                    eprintln!("⚠️ Secret isolation unavailable on this system; child may read its own environment. Set INTERENV_UNSAFE=1 to suppress this warning.");
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
            unsafe {
                libc::kill(pid as i32, libc::SIGINT);
            }
        }
    });

    let status = child.wait().map_err(|e| format!("Process error: {}", e))?;
    child_pid.store(0, Ordering::SeqCst);

    let exit_code = status
        .code()
        .unwrap_or(if status.success() { 0 } else { 1 });
    Ok(exit_code)
}

fn resolve_executable_path(prog: &str) -> String {
    #[cfg(windows)]
    {
        if !prog.ends_with(".exe") && !prog.ends_with(".cmd") && !prog.ends_with(".bat") {
            // Check if <prog>.cmd exists in PATH
            if let Ok(path_var) = std::env::var("PATH") {
                for entry in std::env::split_paths(&path_var) {
                    let cmd_candidate = entry.join(format!("{}.cmd", prog));
                    if cmd_candidate.is_file() {
                        return cmd_candidate.to_string_lossy().to_string();
                    }
                    let exe_candidate = entry.join(format!("{}.exe", prog));
                    if exe_candidate.is_file() {
                        return exe_candidate.to_string_lossy().to_string();
                    }
                    let bat_candidate = entry.join(format!("{}.bat", prog));
                    if bat_candidate.is_file() {
                        return bat_candidate.to_string_lossy().to_string();
                    }
                }
            }
        }
    }
    prog.to_string()
}
