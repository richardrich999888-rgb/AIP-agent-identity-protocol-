//! Bootstrap must create only a transport credential, never a sensor run or
//! a queue bound to a placeholder collector pin.
use std::process::Command;

#[test]
fn key_only_enrollment_is_stable_and_creates_no_queue() {
    let dir = std::env::temp_dir().join(format!(
        "aip-probe-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    let key_path = dir.join("transport.json");
    let invoke = || {
        Command::new(env!("CARGO_BIN_EXE_aip-probe"))
            .arg("init-transport-key")
            .arg(&key_path)
            .env_clear()
            .output()
            .unwrap()
    };
    let first = invoke();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let second = invoke();
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
    let key: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&key_path).unwrap()).unwrap();
    assert_eq!(
        String::from_utf8(first.stdout.clone()).unwrap().trim(),
        key["public_hex"].as_str().unwrap()
    );
    assert!(!String::from_utf8_lossy(&first.stdout).contains(key["private_hex"].as_str().unwrap()));
    assert!(!String::from_utf8_lossy(&first.stderr).contains(key["private_hex"].as_str().unwrap()));
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}
