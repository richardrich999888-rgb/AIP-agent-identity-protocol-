//! These tests bootstrap real transport keys, never sensors or observations.
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn directory(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("vanian-enroll-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn run(id: &str, path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_aip-probe"))
        .args(["enroll", "--probe-id", id, "--key-path"])
        .arg(path)
        .env_clear()
        .output()
        .unwrap()
}

#[test]
fn bootstrap_needs_no_collector_or_sensor_and_exports_only_public_material() {
    let dir = directory("public");
    let path = dir.join("key.json");
    let result = run("host-one", &path);
    assert!(result.status.success());
    let enrollment: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let key: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(enrollment["transport_pubkey_hex"], key["public_hex"]);
    assert_eq!(enrollment["observation"], "NOT_STARTED");
    assert_eq!(enrollment["workload_identity_binding"], "NOT_ESTABLISHED");
    let combined = [result.stdout, result.stderr].concat();
    assert!(!String::from_utf8(combined)
        .unwrap()
        .contains(key["private_hex"].as_str().unwrap()));
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn reenrollment_keeps_the_existing_key() {
    let dir = directory("stable");
    let path = dir.join("key.json");
    assert!(run("host-one", &path).status.success());
    let original = std::fs::read(&path).unwrap();
    assert!(run("host-one", &path).status.success());
    assert_eq!(original, std::fs::read(&path).unwrap());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn invalid_identity_and_relative_path_refused_before_key_creation() {
    let dir = directory("bad-id");
    for id in ["", "line\nbreak", "space name", "../host", &"x".repeat(129)] {
        assert!(!run(id, &dir.join("key.json")).status.success());
    }
    assert!(!run("host", Path::new("relative.json")).status.success());
    assert!(!dir.join("key.json").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_cli_refused_without_starting_daemon() {
    for args in [
        vec!["enroll"],
        vec!["--help"],
        vec!["unknown"],
        vec![
            "enroll",
            "--probe-id",
            "host",
            "--key-path",
            "/tmp/unused",
            "--extra",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_aip-probe"))
            .args(args)
            .env_clear()
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn mismatched_key_pair_refused_and_not_replaced() {
    let dir = directory("mismatch");
    let path = dir.join("key.json");
    assert!(run("host-one", &path).status.success());
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["public_hex"] = serde_json::json!("01".repeat(32));
    std::fs::write(&path, value.to_string()).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert!(!run("host-one", &path).status.success());
    assert_eq!(bytes, std::fs::read(&path).unwrap());
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn symlink_and_readable_private_keys_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = directory("permissions");
    let path = dir.join("key.json");
    assert!(run("host-one", &path).status.success());
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let link = dir.join("link.json");
    symlink(&path, &link).unwrap();
    assert!(!run("host-one", &link).status.success());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!run("host-one", &path).status.success());
    std::fs::remove_dir_all(dir).unwrap();
}
