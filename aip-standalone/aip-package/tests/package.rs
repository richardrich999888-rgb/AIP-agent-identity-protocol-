use aip_package::{build_package, PackageError, PackageFile};

const AIBOM_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn files() -> Vec<PackageFile> {
    vec![
        PackageFile {
            path: "model/weights.bin".into(),
            contents: vec![1, 2, 3, 4],
        },
        PackageFile {
            path: "config/runtime.json".into(),
            contents: br#"{"runtime":"python"}"#.to_vec(),
        },
    ]
}

fn build(files: Vec<PackageFile>) -> aip_package::BuiltPackage {
    build_package("test-agent", "1.0.0", "publisher-test", AIBOM_DIGEST, files)
        .expect("package should build")
}

#[test]
fn identical_inputs_produce_identical_archive_bytes() {
    let first = build(files());
    let second = build(files());

    assert_eq!(first.archive_bytes, second.archive_bytes);
    assert_eq!(first.archive_sha256, second.archive_sha256);
    assert_eq!(first.manifest_bytes, second.manifest_bytes);
}

#[test]
fn input_order_does_not_change_archive() {
    let first = build(files());

    let mut reversed = files();
    reversed.reverse();

    let second = build(reversed);

    assert_eq!(first.archive_bytes, second.archive_bytes);
}

#[test]
fn manifest_inventory_is_sorted() {
    let package = build(files());

    let paths: Vec<&str> = package
        .manifest
        .files
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();

    assert_eq!(paths, vec!["config/runtime.json", "model/weights.bin"]);
}

#[test]
fn manifest_contains_file_sizes_and_hashes() {
    let package = build(files());

    let entry = package
        .manifest
        .files
        .iter()
        .find(|entry| entry.path == "model/weights.bin")
        .unwrap();

    assert_eq!(entry.size, 4);
    assert_eq!(entry.sha256, hex::encode(aip_crypto::sha256(&[1, 2, 3, 4])));
}

#[test]
fn rejects_path_traversal() {
    let input = vec![PackageFile {
        path: "../outside.txt".into(),
        contents: b"unsafe".to_vec(),
    }];

    assert!(matches!(
        build_package("agent", "1.0", "publisher", AIBOM_DIGEST, input),
        Err(PackageError::InvalidPath(_))
    ));
}

#[test]
fn rejects_absolute_paths() {
    let input = vec![PackageFile {
        path: "/etc/passwd".into(),
        contents: b"unsafe".to_vec(),
    }];

    assert!(matches!(
        build_package("agent", "1.0", "publisher", AIBOM_DIGEST, input),
        Err(PackageError::InvalidPath(_))
    ));
}

#[test]
fn rejects_duplicate_paths() {
    let input = vec![
        PackageFile {
            path: "model.bin".into(),
            contents: vec![1],
        },
        PackageFile {
            path: "model.bin".into(),
            contents: vec![2],
        },
    ];

    assert!(matches!(
        build_package("agent", "1.0", "publisher", AIBOM_DIGEST, input),
        Err(PackageError::DuplicatePath(_))
    ));
}

#[test]
fn rejects_reserved_manifest_path() {
    let input = vec![PackageFile {
        path: "aip-package.json".into(),
        contents: b"forged".to_vec(),
    }];

    assert!(matches!(
        build_package("agent", "1.0", "publisher", AIBOM_DIGEST, input),
        Err(PackageError::ReservedPath(_))
    ));
}

#[test]
fn rejects_invalid_aibom_digest() {
    let result = build_package("agent", "1.0", "publisher", "not-a-digest", files());

    assert!(matches!(result, Err(PackageError::InvalidMetadata(_))));
}

#[test]
fn archive_contains_manifest_and_payload_files() {
    use std::io::Read;

    let package = build(files());
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&package.archive_bytes)).unwrap();

    assert_eq!(archive.len(), 3);

    let mut manifest = String::new();
    archive
        .by_name("aip-package.json")
        .unwrap()
        .read_to_string(&mut manifest)
        .unwrap();

    assert_eq!(manifest.as_bytes(), package.manifest_bytes);
    assert!(archive.by_name("model/weights.bin").is_ok());
    assert!(archive.by_name("config/runtime.json").is_ok());
}

use aip_crypto::custody::{Custodian, InMemoryCustodian};
use aip_package::{sign_package, verify_package};

#[test]
fn publisher_can_sign_and_verify_package() {
    let package = build(files());
    let custodian = InMemoryCustodian::generate();

    let signature = sign_package(&package, &custodian).unwrap();

    verify_package(&package, &signature, custodian.public_key(), AIBOM_DIGEST).unwrap();
}

#[test]
fn rejects_wrong_publisher_public_key() {
    let package = build(files());
    let publisher = InMemoryCustodian::generate();
    let attacker = InMemoryCustodian::generate();

    let signature = sign_package(&package, &publisher).unwrap();

    assert!(verify_package(&package, &signature, attacker.public_key(), AIBOM_DIGEST,).is_err());
}

#[test]
fn rejects_wrong_aibom_digest() {
    let package = build(files());
    let publisher = InMemoryCustodian::generate();
    let signature = sign_package(&package, &publisher).unwrap();

    let wrong_digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    assert!(verify_package(&package, &signature, publisher.public_key(), wrong_digest,).is_err());
}

#[test]
fn rejects_modified_archive_bytes() {
    let mut package = build(files());
    let publisher = InMemoryCustodian::generate();
    let signature = sign_package(&package, &publisher).unwrap();

    package.archive_bytes[10] ^= 0xff;

    assert!(verify_package(&package, &signature, publisher.public_key(), AIBOM_DIGEST,).is_err());
}

#[test]
fn rejects_modified_archive_digest_field() {
    let mut package = build(files());
    let publisher = InMemoryCustodian::generate();
    let signature = sign_package(&package, &publisher).unwrap();

    package.archive_sha256[0] ^= 0xff;

    assert!(verify_package(&package, &signature, publisher.public_key(), AIBOM_DIGEST,).is_err());
}

#[test]
fn rejects_modified_package_manifest() {
    let mut package = build(files());
    let publisher = InMemoryCustodian::generate();
    let signature = sign_package(&package, &publisher).unwrap();

    package.manifest.name = "modified-agent".into();

    assert!(verify_package(&package, &signature, publisher.public_key(), AIBOM_DIGEST,).is_err());
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

    let mut entries = Vec::new();

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).unwrap();
        let path = entry.name().unwrap().into_owned();
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents).unwrap();
        entries.push((path, contents));
    }

    entries
}

#[test]
fn rejects_payload_not_matching_manifest_hash() {
    let mut package = build(files());
    let publisher = InMemoryCustodian::generate();

    let mut entries = archive_entries(&package);

    let payload = entries
        .iter_mut()
        .find(|(path, _)| path == "model/weights.bin")
        .unwrap();

    payload.1 = vec![9, 9, 9, 9];

    repack(&mut package, entries);

    let signature = sign_package(&package, &publisher).unwrap();

    assert!(verify_package(&package, &signature, publisher.public_key(), AIBOM_DIGEST,).is_err());
}

#[test]
fn rejects_unexpected_archive_file() {
    let mut package = build(files());
    let publisher = InMemoryCustodian::generate();

    let mut entries = archive_entries(&package);
    entries.push(("unexpected.txt".into(), b"extra".to_vec()));

    repack(&mut package, entries);

    let signature = sign_package(&package, &publisher).unwrap();

    assert!(verify_package(&package, &signature, publisher.public_key(), AIBOM_DIGEST,).is_err());
}

#[test]
fn rejects_missing_payload_file() {
    let mut package = build(files());
    let publisher = InMemoryCustodian::generate();

    let entries = archive_entries(&package)
        .into_iter()
        .filter(|(path, _)| path != "config/runtime.json")
        .collect();

    repack(&mut package, entries);

    let signature = sign_package(&package, &publisher).unwrap();

    assert!(verify_package(&package, &signature, publisher.public_key(), AIBOM_DIGEST,).is_err());
}

#[test]
fn rejects_missing_package_manifest() {
    let mut package = build(files());
    let publisher = InMemoryCustodian::generate();

    let entries = archive_entries(&package)
        .into_iter()
        .filter(|(path, _)| path != "aip-package.json")
        .collect();

    repack(&mut package, entries);

    let signature = sign_package(&package, &publisher).unwrap();

    assert!(verify_package(&package, &signature, publisher.public_key(), AIBOM_DIGEST,).is_err());
}

#[test]
fn rejects_unsupported_signature_algorithm() {
    let package = build(files());
    let publisher = InMemoryCustodian::generate();
    let mut signature = sign_package(&package, &publisher).unwrap();

    signature.signature.algorithm = aip_types::AlgorithmId::Hybrid;

    assert!(verify_package(&package, &signature, publisher.public_key(), AIBOM_DIGEST,).is_err());
}

#[test]
fn rejects_duplicate_zip_entry_names() {
    use std::io::Cursor;

    let input = vec![
        PackageFile {
            path: "a.bin".into(),
            contents: b"first".to_vec(),
        },
        PackageFile {
            path: "b.bin".into(),
            contents: b"second".to_vec(),
        },
    ];

    let mut package = build(input);
    let publisher = InMemoryCustodian::generate();
    let signature = sign_package(&package, &publisher).unwrap();

    let replacement = b"a.bin";
    let original = b"b.bin";

    for index in 0..=package.archive_bytes.len() - original.len() {
        if &package.archive_bytes[index..index + original.len()] == original {
            package.archive_bytes[index..index + replacement.len()].copy_from_slice(replacement);
        }
    }

    let archive = zip::ZipArchive::new(Cursor::new(&package.archive_bytes)).unwrap();
    assert!(archive.has_duplicate_names());

    package.archive_sha256 = aip_crypto::sha256(&package.archive_bytes);

    let result = verify_package(&package, &signature, publisher.public_key(), AIBOM_DIGEST);

    assert!(matches!(
        result,
        Err(PackageError::InvalidMetadata(message))
            if message.contains("duplicate ZIP entry names")
    ));
}

use aip_package::{build_package_v2, PACKAGE_FORMAT_VERSION_V2};

#[test]
fn v2_package_declares_and_verifies_executables() {
    let package = build_package_v2(
        "test-agent",
        "2.0.0",
        "publisher-test",
        AIBOM_DIGEST,
        files(),
        vec!["model/weights.bin".into()],
    )
    .unwrap();

    assert_eq!(package.manifest.format_version, PACKAGE_FORMAT_VERSION_V2);

    let executable = package
        .manifest
        .files
        .iter()
        .find(|entry| entry.path == "model/weights.bin")
        .unwrap();
    let data = package
        .manifest
        .files
        .iter()
        .find(|entry| entry.path == "config/runtime.json")
        .unwrap();

    assert!(executable.executable);
    assert!(!data.executable);

    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&package.archive_bytes)).unwrap();

    assert_eq!(
        archive
            .by_name("model/weights.bin")
            .unwrap()
            .unix_mode()
            .unwrap()
            & 0o777,
        0o755
    );
    assert_eq!(
        archive
            .by_name("config/runtime.json")
            .unwrap()
            .unix_mode()
            .unwrap()
            & 0o777,
        0o644
    );

    let publisher = InMemoryCustodian::generate();
    let signature = sign_package(&package, &publisher).unwrap();

    verify_package(&package, &signature, publisher.public_key(), AIBOM_DIGEST).unwrap();
}

#[test]
fn v2_package_build_is_deterministic() {
    let first = build_package_v2(
        "test-agent",
        "2.0.0",
        "publisher-test",
        AIBOM_DIGEST,
        files(),
        vec!["model/weights.bin".into()],
    )
    .unwrap();

    let second = build_package_v2(
        "test-agent",
        "2.0.0",
        "publisher-test",
        AIBOM_DIGEST,
        files(),
        vec!["model/weights.bin".into()],
    )
    .unwrap();

    assert_eq!(first.archive_bytes, second.archive_bytes);
    assert_eq!(first.manifest_bytes, second.manifest_bytes);
}

#[test]
fn v2_rejects_executable_declaration_for_missing_file() {
    let result = build_package_v2(
        "test-agent",
        "2.0.0",
        "publisher-test",
        AIBOM_DIGEST,
        files(),
        vec!["bin/not-present".into()],
    );

    assert!(matches!(result, Err(PackageError::InvalidMetadata(_))));
}

#[test]
fn v2_rejects_traversal_in_executable_declaration() {
    let result = build_package_v2(
        "test-agent",
        "2.0.0",
        "publisher-test",
        AIBOM_DIGEST,
        files(),
        vec!["../outside".into()],
    );

    assert!(matches!(result, Err(PackageError::InvalidPath(_))));
}

#[test]
fn v2_executable_metadata_is_bound_to_signed_manifest() {
    let mut package = build_package_v2(
        "test-agent",
        "2.0.0",
        "publisher-test",
        AIBOM_DIGEST,
        files(),
        vec!["model/weights.bin".into()],
    )
    .unwrap();

    let publisher = InMemoryCustodian::generate();
    let signature = sign_package(&package, &publisher).unwrap();

    package
        .manifest
        .files
        .iter_mut()
        .find(|entry| entry.path == "model/weights.bin")
        .unwrap()
        .executable = false;

    assert!(verify_package(&package, &signature, publisher.public_key(), AIBOM_DIGEST).is_err());
}

#[test]
fn v2_rejects_duplicate_executable_declarations() {
    let result = build_package_v2(
        "test-agent",
        "2.0.0",
        "publisher-test",
        AIBOM_DIGEST,
        files(),
        vec!["model/weights.bin".into(), "model/weights.bin".into()],
    );

    assert!(matches!(result, Err(PackageError::InvalidMetadata(_))));
}

#[test]
fn v1_manifest_remains_backward_compatible() {
    let package = aip_package::build_package(
        "test-agent",
        "1.0.0",
        "publisher-test",
        AIBOM_DIGEST,
        files(),
    )
    .unwrap();

    assert_eq!(
        package.manifest.format_version,
        aip_package::PACKAGE_FORMAT_VERSION
    );

    let manifest_json = String::from_utf8(package.manifest_bytes.clone()).unwrap();
    assert!(!manifest_json.contains("\"executable\":"));

    let publisher = InMemoryCustodian::generate();
    let signature = sign_package(&package, &publisher).unwrap();

    verify_package(&package, &signature, publisher.public_key(), AIBOM_DIGEST).unwrap();
}

#[test]
fn verified_package_returns_only_authenticated_file_contents() {
    let package = build(files());
    let publisher = InMemoryCustodian::generate();
    let signature = sign_package(&package, &publisher).unwrap();

    let verified = aip_package::verify_package_contents(
        &package,
        &signature,
        publisher.public_key(),
        AIBOM_DIGEST,
    )
    .expect("valid signed package should return verified contents");

    assert_eq!(verified.manifest().name, "test-agent");
    assert_eq!(verified.manifest().publisher_id, "publisher-test");
    assert_eq!(verified.files().len(), 2);

    let config = verified
        .files()
        .iter()
        .find(|file| file.path() == "config/runtime.json")
        .unwrap();

    assert_eq!(config.contents(), br#"{"runtime":"python"}"#);
    assert!(!config.is_executable());

    let weights = verified
        .files()
        .iter()
        .find(|file| file.path() == "model/weights.bin")
        .unwrap();

    assert_eq!(weights.contents(), &[1, 2, 3, 4]);
    assert!(!weights.is_executable());
}

#[test]
fn rejects_untrusted_publisher_when_returning_verified_contents() {
    let package = build(files());
    let publisher = InMemoryCustodian::generate();
    let attacker = InMemoryCustodian::generate();

    let signature = sign_package(&package, &publisher).unwrap();

    assert!(aip_package::verify_package_contents(
        &package,
        &signature,
        attacker.public_key(),
        AIBOM_DIGEST,
    )
    .is_err());
}
