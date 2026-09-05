#[cfg(target_os = "linux")]
#[test]
fn test_runner_isolation() {
    use interenv::envfile::Secrets;
    use interenv::runner::execute_with_env;
    use std::collections::BTreeMap;
    use zeroize::Zeroizing;

    let mut map = BTreeMap::new();
    map.insert(
        "MY_TEST_SECRET".to_string(),
        Zeroizing::new("supersecret123".to_string()),
    );
    let secrets = Secrets(map);

    let program = "/bin/sh";
    let args = vec![
        "-c".to_string(),
        "cat /proc/self/environ | grep -c INTERENV_PROTECTED".to_string(),
    ];

    let res = execute_with_env(program, &args, &secrets);
    assert!(res.is_ok());
}
