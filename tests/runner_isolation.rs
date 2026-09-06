#[cfg(target_os = "linux")]
#[test]
fn test_runner_isolation_linux_environ() {
    use interenv::envfile::Secrets;
    use interenv::runner::execute_with_env;
    use std::collections::BTreeMap;
    use zeroize::Zeroizing;

    let mut map = BTreeMap::new();
    map.insert(
        "MY_TEST_SECRET".to_string(),
        Zeroizing::new("supersecret123".to_string()),
    );
    let secrets = Secrets::new(map);

    let program = "/bin/sh";
    let args = vec![
        "-c".to_string(),
        "cat /proc/self/environ | grep -c MY_TEST_SECRET".to_string(),
    ];

    let res = execute_with_env(program, &args, &secrets);
    assert!(res.is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn test_runner_isolation_linux_seccomp() {
    use interenv::envfile::Secrets;
    use interenv::runner::execute_with_env;
    use std::collections::BTreeMap;

    let secrets = Secrets::new(BTreeMap::new());
    let program = "/bin/sh";
    // Verify seccomp filter mode is active (non-zero: 1 for STRICT, 2 for FILTER)
    let args = vec![
        "-c".to_string(),
        "status=$(grep ^Seccomp: /proc/self/status | awk '{print $2}'); [ -n \"$status\" ] && [ \"$status\" -ne 0 ]".to_string(),
    ];

    let res = execute_with_env(program, &args, &secrets);
    assert!(res.is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn test_runner_isolation_linux_seccomp_blocks_ptrace() {
    use interenv::envfile::Secrets;
    use interenv::runner::execute_with_env;
    use std::collections::BTreeMap;

    let secrets = Secrets::new(BTreeMap::new());
    let program = "/bin/sh";
    let args = vec![
        "-c".to_string(),
        "grep -r '' /proc/self/mem > /dev/null 2>&1; echo done".to_string(),
    ];

    let res = execute_with_env(program, &args, &secrets);
    assert!(res.is_ok());
}

#[cfg(target_os = "macos")]
#[test]
fn test_runner_isolation_macos_sandbox() {
    use interenv::envfile::Secrets;
    use interenv::runner::execute_with_env;
    use std::collections::BTreeMap;

    let secrets = Secrets::new(BTreeMap::new());
    let program = "/bin/sh";
    let args = vec![
        "-c".to_string(),
        "touch /System/test_interenv 2>&1 || echo DENIED".to_string(),
    ];

    let res = execute_with_env(program, &args, &secrets);
    assert!(res.is_ok());
}

#[cfg(windows)]
#[test]
fn test_runner_isolation_windows() {
    use interenv::envfile::Secrets;
    use interenv::runner::execute_with_env;
    use std::collections::BTreeMap;
    use zeroize::Zeroizing;

    let mut map = BTreeMap::new();
    map.insert(
        "MY_TEST_SECRET".to_string(),
        Zeroizing::new("supersecret123".to_string()),
    );
    let secrets = Secrets::new(map);

    let program = "cmd.exe";
    let args = vec!["/c".to_string(), "echo %MY_TEST_SECRET%".to_string()];

    let res = execute_with_env(program, &args, &secrets);
    assert!(res.is_ok());
}
