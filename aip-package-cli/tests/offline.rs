use aip_crypto::custody::{Custodian, InMemoryCustodian};
use aip_package::{build_package, export_package, sign_package, PackageFile};
use base64::Engine;

const AIBOM_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn build(files: Vec<PackageFile>) -> aip_package::BuiltPackage {
    build_package("test-agent", "1.0.0", "publisher-test", AIBOM_DIGEST, files).unwrap()
}

fn repack(package: &mut aip_package::BuiltPackage, entries: Vec<(String, Vec<u8>)>) {
    use std::io::Write;
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
        for (path, contents) in entries {
            writer.start_file(path, options).unwrap();
            writer.write_all(&contents).unwrap();
        }
        writer.finish().unwrap();
    }
    package.archive_bytes = cursor.into_inner();
    package.archive_sha256 = aip_crypto::sha256(&package.archive_bytes);
}

fn archive_entries(package: &aip_package::BuiltPackage) -> Vec<(String, Vec<u8>)> {
    use std::io::Read;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&package.archive_bytes)).unwrap();
    (0..archive.len())
        .map(|index| {
            let mut entry = archive.by_index(index).unwrap();
            let path = entry.name().unwrap().into_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            (path, bytes)
        })
        .collect()
}

struct DiskFixture {
    root: std::path::PathBuf,
    export: std::path::PathBuf,
    anchors: std::path::PathBuf,
    output: std::path::PathBuf,
    value: serde_json::Value,
}

fn disk_fixture(version: &str) -> DiskFixture {
    use std::time::{SystemTime, UNIX_EPOCH};
    let root = std::env::temp_dir().join(format!(
        "aip-package-offline-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let publisher = InMemoryCustodian::generate();
    let package = aip_package::build_package(
        "test-agent",
        version,
        "publisher-test",
        AIBOM_DIGEST,
        vec![PackageFile {
            path: "payload.sh".into(),
            contents: b"#!/bin/sh\ntouch SHOULD_NOT_EXIST\n".to_vec(),
        }],
    )
    .unwrap();
    let signature = sign_package(&package, &publisher).unwrap();
    let export = export_package(&package, &signature).unwrap();
    let value = serde_json::to_value(export).unwrap();
    let anchors_value = serde_json::json!({
        "version": 1,
        "publishers": [{
            "publisher_id": "publisher-test",
            "public_key_hex": hex::encode(publisher.public_key())
        }]
    });
    let export_path = root.join("export.json");
    let anchors = root.join("anchors.json");
    std::fs::write(&export_path, serde_json::to_vec(&value).unwrap()).unwrap();
    std::fs::write(&anchors, serde_json::to_vec(&anchors_value).unwrap()).unwrap();
    DiskFixture {
        output: root.join("out"),
        root,
        export: export_path,
        anchors,
        value,
    }
}

fn run_offline_cli(f: &DiskFixture, extra: &[&str]) -> std::process::Output {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_aip-package"));
    command.args([
        "verify",
        "--package",
        f.export.to_str().unwrap(),
        "--anchors",
        f.anchors.to_str().unwrap(),
        "--output-dir",
        f.output.to_str().unwrap(),
    ]);
    if !extra.iter().any(|arg| *arg == "--aibom-digest") {
        command.args(["--aibom-digest", AIBOM_DIGEST]);
    }
    command.args(extra);
    command.output().unwrap()
}

fn store_export(f: &DiskFixture, value: &serde_json::Value) {
    std::fs::write(&f.export, serde_json::to_vec(value).unwrap()).unwrap();
}

#[test]
fn offline_cli_verifies_disk_export_and_extracts_without_executing_payload() {
    let f = disk_fixture("1.2.3");
    let result = run_offline_cli(
        &f,
        &[
            "--accepted-name",
            "test-agent",
            "--minimum-version",
            "1.2.0",
        ],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["status"], "VERIFIED");
    assert_eq!(report["signature_verified"], true);
    assert_eq!(report["inventory_verified"], true);
    assert_eq!(report["policy_accepted"], true);
    assert_eq!(
        std::fs::read(f.output.join("payload.sh")).unwrap(),
        b"#!/bin/sh\ntouch SHOULD_NOT_EXIST\n"
    );
    assert!(!f.output.join("SHOULD_NOT_EXIST").exists());
    std::fs::remove_dir_all(f.root).unwrap();
}

#[test]
fn offline_cli_rejects_modified_archive() {
    let f = disk_fixture("1.2.3");
    let mut value = f.value.clone();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value["archive_base64"].as_str().unwrap())
        .unwrap();
    let mut bytes = bytes;
    bytes[20] ^= 1;
    value["archive_base64"] =
        serde_json::json!(base64::engine::general_purpose::STANDARD.encode(bytes));
    store_export(&f, &value);
    assert!(!run_offline_cli(&f, &[]).status.success());
    assert!(!f.output.exists());
    std::fs::remove_dir_all(f.root).unwrap();
}

#[test]
fn offline_cli_rejects_modified_embedded_manifest() {
    let f = disk_fixture("1.2.3");
    let mut value = f.value.clone();
    value["manifest"]["name"] = serde_json::json!("substituted-agent");
    let original = base64::engine::general_purpose::STANDARD
        .decode(value["archive_base64"].as_str().unwrap())
        .unwrap();
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(original)).unwrap();
    let mut entries = Vec::new();
    for index in 0..archive.len() {
        use std::io::Read;
        let mut entry = archive.by_index(index).unwrap();
        let path = entry.name().unwrap().into_owned();
        let mut content = Vec::new();
        entry.read_to_end(&mut content).unwrap();
        if path == "aip-package.json" {
            let mut embedded: serde_json::Value = serde_json::from_slice(&content).unwrap();
            embedded["name"] = serde_json::json!("substituted-agent");
            content = serde_json::to_vec(&embedded).unwrap();
        }
        entries.push((path, content));
    }
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
        for (path, contents) in entries {
            writer.start_file(path, options).unwrap();
            use std::io::Write;
            writer.write_all(&contents).unwrap();
        }
        writer.finish().unwrap();
    }
    let changed_archive = cursor.into_inner();
    value["archive_base64"] =
        serde_json::json!(base64::engine::general_purpose::STANDARD.encode(&changed_archive));
    value["archive_sha256"] = serde_json::json!(hex::encode(aip_crypto::sha256(&changed_archive)));
    store_export(&f, &value);
    assert!(!run_offline_cli(&f, &[]).status.success());
    assert!(!f.output.exists());
    std::fs::remove_dir_all(f.root).unwrap();
}

#[test]
fn offline_cli_rejects_modified_detached_signature() {
    let f = disk_fixture("1.2.3");
    let mut value = f.value.clone();
    value["signature"]["signature_bytes"][0] = serde_json::json!(0);
    store_export(&f, &value);
    assert!(!run_offline_cli(&f, &[]).status.success());
    assert!(!f.output.exists());
    std::fs::remove_dir_all(f.root).unwrap();
}

#[test]
fn offline_cli_rejects_wrong_or_missing_publisher_anchor() {
    let f = disk_fixture("1.2.3");
    let wrong = InMemoryCustodian::generate();
    std::fs::write(&f.anchors, serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "publishers": [{"publisher_id":"publisher-test", "public_key_hex":hex::encode(wrong.public_key())}]
    })).unwrap()).unwrap();
    assert!(!run_offline_cli(&f, &[]).status.success());
    std::fs::remove_file(&f.anchors).unwrap();
    assert!(!run_offline_cli(&f, &[]).status.success());
    assert!(!f.output.exists());
    std::fs::remove_dir_all(f.root).unwrap();
}

#[test]
fn offline_cli_rejects_wrong_aibom_digest() {
    let f = disk_fixture("1.2.3");
    let wrong = "b".repeat(64);
    let result = run_offline_cli(&f, &["--aibom-digest", &wrong]);
    assert!(!result.status.success());
    assert!(!f.output.exists());
    std::fs::remove_dir_all(f.root).unwrap();
}

#[test]
fn offline_cli_rejects_unknown_format_and_truncated_export() {
    let f = disk_fixture("1.2.3");
    let mut value = f.value.clone();
    value["export_version"] = serde_json::json!(99);
    store_export(&f, &value);
    assert!(!run_offline_cli(&f, &[]).status.success());
    let mut value = f.value.clone();
    value["package_format_version"] = serde_json::json!(99);
    value["manifest"]["format_version"] = serde_json::json!(99);
    store_export(&f, &value);
    assert!(!run_offline_cli(&f, &[]).status.success());
    std::fs::write(&f.export, b"{\"export_version\":").unwrap();
    assert!(!run_offline_cli(&f, &[]).status.success());
    assert!(!f.output.exists());
    std::fs::remove_dir_all(f.root).unwrap();
}

#[test]
fn offline_cli_rejects_unknown_schema_fields() {
    let f = disk_fixture("1.2.3");
    let mut value = f.value.clone();
    value["unexpected"] = serde_json::json!(true);
    store_export(&f, &value);
    assert!(!run_offline_cli(&f, &[]).status.success());
    assert!(!f.output.exists());
    std::fs::remove_dir_all(f.root).unwrap();
}

#[test]
fn offline_cli_rejects_unexpected_archive_inventory() {
    let f = disk_fixture("1.2.3");
    let mut package = build(vec![PackageFile {
        path: "known.bin".into(),
        contents: b"known".to_vec(),
    }]);
    let publisher = InMemoryCustodian::generate();
    let mut entries = archive_entries(&package);
    entries.push(("unexpected.bin".into(), b"surprise".to_vec()));
    repack(&mut package, entries);
    let signature = sign_package(&package, &publisher).unwrap();
    let value = serde_json::to_value(export_package(&package, &signature).unwrap()).unwrap();
    store_export(&f, &value);
    std::fs::write(&f.anchors, serde_json::to_vec(&serde_json::json!({"version":1,"publishers":[{"publisher_id":"publisher-test","public_key_hex":hex::encode(publisher.public_key())}]})).unwrap()).unwrap();
    assert!(!run_offline_cli(&f, &[]).status.success());
    assert!(!f.output.exists());
    std::fs::remove_dir_all(f.root).unwrap();
}

#[test]
fn offline_cli_applies_minimum_version_and_revocation_policy() {
    let f = disk_fixture("1.2.3");
    assert!(!run_offline_cli(&f, &["--minimum-version", "1.3.0"])
        .status
        .success());
    assert!(!f.output.exists());
    assert!(
        !run_offline_cli(&f, &["--revoked-publisher", "publisher-test"])
            .status
            .success()
    );
    assert!(!run_offline_cli(
        &f,
        &["--revoked-release", "publisher-test/test-agent@1.2.3"]
    )
    .status
    .success());
    assert!(!run_offline_cli(&f, &["--minimum-version", "1.2.3-rc1"])
        .status
        .success());
    assert!(!f.output.exists());
    std::fs::remove_dir_all(f.root).unwrap();
}
