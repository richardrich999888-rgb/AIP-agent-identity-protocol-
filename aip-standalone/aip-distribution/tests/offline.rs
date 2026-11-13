use aip_crypto::custody::{Custodian, InMemoryCustodian};
use aip_distribution::*;
use aip_package::{build_package, build_package_v2, export_package, sign_package, PackageFile};
use std::path::PathBuf;
const AIBOM_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn partial_dir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "aip-dist-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn disk_fixture(
    v2: bool,
    payload: Vec<u8>,
) -> (
    TransferManifest,
    Vec<TransferChunk>,
    std::sync::Arc<InMemoryCustodian>,
) {
    let publisher = signer();
    let export = package(v2, publisher.as_ref(), AIBOM_DIGEST, payload);
    let (manifest, chunks) = create_manifest(&export, publisher.as_ref()).unwrap();
    (manifest, chunks, publisher)
}
fn package(v2: bool, signer: &dyn Custodian, aibom_digest: &str, payload: Vec<u8>) -> Vec<u8> {
    let f = vec![PackageFile {
        path: "model.bin".into(),
        contents: payload,
    }];
    let p = if v2 {
        build_package_v2("agent", "1.0.0", "publisher", aibom_digest, f, vec![]).unwrap()
    } else {
        build_package("agent", "1.0.0", "publisher", aibom_digest, f).unwrap()
    };
    let s = sign_package(&p, signer).unwrap();
    serde_json::to_vec(&export_package(&p, &s).unwrap()).unwrap()
}
fn signer() -> std::sync::Arc<InMemoryCustodian> {
    let seed = [9; 32];
    std::sync::Arc::new(
        InMemoryCustodian::new(&seed, &aip_crypto::public_key_from_private(&seed).unwrap())
            .unwrap(),
    )
}
fn noisy_payload(len: usize) -> Vec<u8> {
    let mut x = 0x1234_5678u32;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

#[test]
fn valid_v1_and_v2_exports_reassemble_and_independently_verify() {
    // Kept independent from transfer verification: package verifier checks the archive/signature/inventory.
    for v2 in [false, true] {
        let publisher = signer();
        let d = AIBOM_DIGEST;
        let bytes = package(
            v2,
            publisher.as_ref(),
            &d,
            b"payload-is-never-executed".to_vec(),
        );
        let (tm, chunks) = create_manifest(&bytes, publisher.as_ref()).unwrap();
        let mut receiver =
            TransferReceiver::new(tm.clone(), "publisher", publisher.public_key()).unwrap();
        for c in &chunks {
            receiver.accept(c.clone()).unwrap();
        }
        let mut wrong_key = TransferReceiver::new(tm, "publisher", publisher.public_key()).unwrap();
        for c in chunks {
            wrong_key.accept(c).unwrap();
        }
        assert!(wrong_key.verify_complete("publisher", &[0; 32], d).is_err());
        let verified = receiver
            .verify_complete("publisher", publisher.public_key(), d)
            .unwrap();
        assert_eq!(verified.manifest().format_version, if v2 { 2 } else { 1 });
        assert_eq!(verified.files()[0].contents(), b"payload-is-never-executed");
    }
}

#[test]
fn rejects_tampered_signature_wrong_anchor_and_chunk_substitution() {
    let signer = signer();
    let d = AIBOM_DIGEST;
    let bytes = package(false, signer.as_ref(), &d, b"x".to_vec());
    let (mut tm, _chunks) = create_manifest(&bytes, signer.as_ref()).unwrap();
    tm.merkle_root = "00".repeat(32);
    assert!(verify_manifest(&tm, "publisher", signer.public_key()).is_err());
    let (mut bad_signature, _) = create_manifest(&bytes, signer.as_ref()).unwrap();
    bad_signature.signature.signature_bytes[0] ^= 1;
    assert!(verify_manifest(&bad_signature, "publisher", signer.public_key()).is_err());
    let (tm, chunks) = create_manifest(&bytes, signer.as_ref()).unwrap();
    assert!(verify_manifest(&tm, "publisher", &[0; 32]).is_err());
    let mut c = chunks[0].clone();
    c.bytes[0] ^= 1;
    assert!(verify_chunk(&tm, &c).is_err());
    let mut wrong = chunks[0].clone();
    wrong.index = 1;
    assert!(verify_chunk(&tm, &wrong).is_err());
}

#[test]
fn receiver_rejects_duplicate_reordered_cross_transfer_and_missing_chunks() {
    let signer = signer();
    let d = AIBOM_DIGEST;
    let bytes = package(false, signer.as_ref(), &d, noisy_payload(CHUNK_SIZE + 20));
    let (tm, chunks) = create_manifest(&bytes, signer.as_ref()).unwrap();
    let mut r = TransferReceiver::new(tm.clone(), "publisher", signer.public_key()).unwrap();
    assert!(r
        .accept(TransferChunk {
            index: 1,
            bytes: vec![],
            proof: vec![]
        })
        .is_err());
    assert!(r.accept(chunks[0].clone()).is_ok());
    assert!(r.accept(chunks[0].clone()).is_err());
    let other_bytes = package(false, signer.as_ref(), &d, b"other".to_vec());
    let (other, foreign) = create_manifest(&other_bytes, signer.as_ref()).unwrap();
    assert_ne!(other.transfer_id, tm.transfer_id);
    assert!(verify_chunk(&tm, &foreign[0]).is_err());
    assert!(verify_chunk(&tm, &chunks[1]).is_ok());
    let mut bad_final = chunks[1].clone();
    bad_final.bytes.pop();
    assert!(verify_chunk(&tm, &bad_final).is_err());
    let mut oversized = chunks[0].clone();
    oversized.bytes.push(0);
    assert!(verify_chunk(&tm, &oversized).is_err());
    let state_bytes = serde_json::to_vec(&r.resume_state()).unwrap();
    let state: ResumeState = serde_json::from_slice(&state_bytes).unwrap();
    let resumed = TransferReceiver::resume(state, "publisher", signer.public_key()).unwrap();
    assert_eq!(resumed.resume_state().chunks.len(), 1);
    assert!(r
        .verify_complete("publisher", signer.public_key(), d)
        .is_err());
}

#[test]
fn oversized_transfer_and_malformed_manifest_are_rejected() {
    let signer = signer();
    let d = AIBOM_DIGEST;
    let bytes = package(false, signer.as_ref(), &d, b"x".to_vec());
    let (mut tm, _) = create_manifest(&bytes, signer.as_ref()).unwrap();
    tm.export_len = MAX_TRANSFER_BYTES + 1;
    assert!(verify_manifest(&tm, "publisher", signer.public_key()).is_err());
    assert!(create_manifest(&[], signer.as_ref()).is_err());
    assert!(create_manifest(br#"{"export_version":1,"unknown":true}"#, signer.as_ref()).is_err());
    assert!(parse_manifest(&vec![b' '; MAX_MANIFEST_JSON_BYTES + 1]).is_err());
    assert!(parse_manifest(br#"{"version":1,"unknown":true}"#).is_err());
}

#[test]
fn resume_revalidates_proofs_and_wrong_aibom_is_rejected() {
    let signer = signer();
    let d = AIBOM_DIGEST;
    let bytes = package(false, signer.as_ref(), &d, noisy_payload(CHUNK_SIZE + 3));
    let (tm, chunks) = create_manifest(&bytes, signer.as_ref()).unwrap();
    let mut receiver = TransferReceiver::new(tm.clone(), "publisher", signer.public_key()).unwrap();
    receiver.accept(chunks[0].clone()).unwrap();
    let mut state = receiver.resume_state();
    state.chunks[0].bytes[0] ^= 1;
    assert!(TransferReceiver::resume(state, "publisher", signer.public_key()).is_err());
    let mut receiver = TransferReceiver::new(tm, "publisher", signer.public_key()).unwrap();
    for c in chunks {
        receiver.accept(c).unwrap();
    }
    let wrong = "00".repeat(32);
    assert!(receiver
        .verify_complete("publisher", signer.public_key(), &wrong)
        .is_err());

    let wrong_digest = "00".repeat(32);
    let bytes = package(
        false,
        signer.as_ref(),
        &wrong_digest,
        b"digest mismatch".to_vec(),
    );
    let (tm, chunks) = create_manifest(&bytes, signer.as_ref()).unwrap();
    let mut receiver = TransferReceiver::new(tm, "publisher", signer.public_key()).unwrap();
    for chunk in chunks {
        receiver.accept(chunk).unwrap();
    }
    assert!(receiver
        .verify_complete("publisher", signer.public_key(), AIBOM_DIGEST)
        .is_err());
}

#[cfg(unix)]
#[test]
fn disk_receiver_verifies_v1_and_v2_without_execution() {
    for v2 in [false, true] {
        let (manifest, chunks, publisher) = disk_fixture(v2, b"disk-payload".to_vec());
        let dir = partial_dir("valid");
        let mut receiver =
            DiskTransferReceiver::create(&dir, manifest, "publisher", publisher.public_key())
                .unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for file in ["manifest.json", "chunks.bin", "journal.json", "writer.lock"] {
            assert_eq!(
                std::fs::metadata(dir.join(file))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        for chunk in chunks {
            receiver.accept(chunk).unwrap();
        }
        let verified = receiver
            .finalize("publisher", publisher.public_key(), AIBOM_DIGEST)
            .unwrap();
        assert_eq!(verified.manifest().format_version, if v2 { 2 } else { 1 });
        assert_eq!(verified.files()[0].contents(), b"disk-payload");
        assert!(!dir.join("SHOULD_NOT_EXECUTE").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn disk_restart_resumes_and_recovers_interrupted_atomic_journal_update() {
    let (manifest, chunks, publisher) = disk_fixture(false, noisy_payload(CHUNK_SIZE + 17));
    let dir = partial_dir("resume");
    let mut receiver =
        DiskTransferReceiver::create(&dir, manifest, "publisher", publisher.public_key()).unwrap();
    receiver.accept(chunks[0].clone()).unwrap();
    assert_eq!(receiver.completed_chunks(), 1);
    assert!(DiskTransferReceiver::resume(&dir, "publisher", publisher.public_key()).is_err());
    drop(receiver);

    // Simulate chunk data reaching disk immediately before a process crash,
    // before its journal entry can be atomically installed.
    use std::io::{Seek, SeekFrom, Write};
    let mut data = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("chunks.bin"))
        .unwrap();
    data.seek(SeekFrom::Start(CHUNK_SIZE as u64)).unwrap();
    data.write_all(&chunks[1].bytes).unwrap();
    data.sync_all().unwrap();
    drop(data);

    // A crash can leave the pre-rename temp file; the installed journal still
    // determines completion, and the temp is discarded during safe recovery.
    std::fs::write(dir.join("journal.tmp"), b"partial journal").unwrap();
    let mut resumed =
        DiskTransferReceiver::resume(&dir, "publisher", publisher.public_key()).unwrap();
    assert_eq!(resumed.completed_chunks(), 1);
    assert!(!dir.join("journal.tmp").exists());
    for chunk in chunks.into_iter().skip(1) {
        resumed.accept(chunk).unwrap();
    }
    assert!(resumed
        .finalize("publisher", publisher.public_key(), AIBOM_DIGEST)
        .is_ok());
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn disk_resume_detects_modified_truncated_and_corrupt_journal_data() {
    let (manifest, chunks, publisher) = disk_fixture(false, noisy_payload(CHUNK_SIZE + 9));
    let dir = partial_dir("modified");
    let mut receiver =
        DiskTransferReceiver::create(&dir, manifest, "publisher", publisher.public_key()).unwrap();
    receiver.accept(chunks[0].clone()).unwrap();
    drop(receiver);
    use std::io::{Seek, SeekFrom, Write};
    let mut data = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("chunks.bin"))
        .unwrap();
    data.seek(SeekFrom::Start(3)).unwrap();
    data.write_all(&[0xff]).unwrap();
    data.sync_all().unwrap();
    drop(data);
    assert!(DiskTransferReceiver::resume(&dir, "publisher", publisher.public_key()).is_err());
    std::fs::remove_dir_all(&dir).unwrap();

    let (manifest, chunks, publisher) = disk_fixture(false, noisy_payload(CHUNK_SIZE + 9));
    let dir = partial_dir("truncated");
    let mut receiver =
        DiskTransferReceiver::create(&dir, manifest, "publisher", publisher.public_key()).unwrap();
    receiver.accept(chunks[0].clone()).unwrap();
    drop(receiver);
    std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("chunks.bin"))
        .unwrap()
        .set_len(1)
        .unwrap();
    assert!(DiskTransferReceiver::resume(&dir, "publisher", publisher.public_key()).is_err());
    std::fs::remove_dir_all(&dir).unwrap();

    let (manifest, _chunks, publisher) = disk_fixture(false, b"journal".to_vec());
    let dir = partial_dir("journal");
    let receiver =
        DiskTransferReceiver::create(&dir, manifest, "publisher", publisher.public_key()).unwrap();
    drop(receiver);
    std::fs::write(dir.join("journal.json"), b"not-json").unwrap();
    assert!(DiskTransferReceiver::resume(&dir, "publisher", publisher.public_key()).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn disk_receiver_rejects_symlinks_unexpected_types_and_traversal() {
    use std::os::unix::fs::symlink;
    let publisher = signer();
    let (manifest, _, _) = disk_fixture(false, b"x".to_vec());
    let real = partial_dir("real");
    std::fs::create_dir(&real).unwrap();
    let link = partial_dir("link");
    symlink(&real, &link).unwrap();
    assert!(DiskTransferReceiver::create(
        &link,
        manifest.clone(),
        "publisher",
        publisher.public_key()
    )
    .is_err());
    std::fs::remove_file(&link).unwrap();
    std::fs::remove_dir_all(&real).unwrap();

    let traversal = std::env::temp_dir()
        .join("aip-dist-parent")
        .join("..")
        .join("escape");
    assert!(
        DiskTransferReceiver::create(traversal, manifest, "publisher", publisher.public_key())
            .is_err()
    );

    let (manifest, _, publisher) = disk_fixture(false, b"x".to_vec());
    let dir = partial_dir("unexpected");
    let receiver =
        DiskTransferReceiver::create(&dir, manifest, "publisher", publisher.public_key()).unwrap();
    drop(receiver);
    std::fs::create_dir(dir.join("unexpected-entry")).unwrap();
    assert!(DiskTransferReceiver::resume(&dir, "publisher", publisher.public_key()).is_err());
    std::fs::remove_dir_all(dir).unwrap();

    let (manifest, _, publisher) = disk_fixture(false, b"symlink entry".to_vec());
    let dir = partial_dir("symlink-entry");
    let receiver =
        DiskTransferReceiver::create(&dir, manifest, "publisher", publisher.public_key()).unwrap();
    drop(receiver);
    let target = partial_dir("symlink-target");
    std::fs::write(&target, b"target").unwrap();
    std::fs::remove_file(dir.join("journal.json")).unwrap();
    symlink(&target, dir.join("journal.json")).unwrap();
    assert!(DiskTransferReceiver::resume(&dir, "publisher", publisher.public_key()).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_file(target).unwrap();
}

#[cfg(unix)]
#[test]
fn disk_receiver_rejects_invalid_proofs_cross_transfer_duplicates_and_incomplete_finalize() {
    let (manifest, chunks, publisher) = disk_fixture(false, noisy_payload(CHUNK_SIZE + 5));
    let dir = partial_dir("proof");
    let mut receiver =
        DiskTransferReceiver::create(&dir, manifest.clone(), "publisher", publisher.public_key())
            .unwrap();
    let mut bad = chunks[0].clone();
    bad.bytes[0] ^= 1;
    assert!(receiver.accept(bad).is_err());
    assert_eq!(receiver.completed_chunks(), 0);
    let mut oversized = chunks[0].clone();
    oversized.bytes.push(0);
    assert!(receiver.accept(oversized).is_err());
    let (other_manifest, other_chunks, _) = disk_fixture(false, b"different".to_vec());
    assert_ne!(manifest.transfer_id, other_manifest.transfer_id);
    assert!(receiver.accept(other_chunks[0].clone()).is_err());
    receiver.accept(chunks[0].clone()).unwrap();
    assert!(receiver.accept(chunks[0].clone()).is_err());
    assert_eq!(receiver.completed_chunks(), 1);
    assert!(receiver
        .finalize("publisher", publisher.public_key(), AIBOM_DIGEST)
        .is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[test]
fn disk_create_rejects_oversized_transfer_before_creating_storage() {
    let (mut manifest, _, publisher) = disk_fixture(false, b"small".to_vec());
    manifest.export_len = MAX_TRANSFER_BYTES + 1;
    let dir = partial_dir("oversized");
    assert!(
        DiskTransferReceiver::create(&dir, manifest, "publisher", publisher.public_key()).is_err()
    );
    assert!(!dir.exists());
}

#[cfg(unix)]
#[test]
fn disk_finalize_rejects_bad_package_signature_and_aibom_binding() {
    let publisher = signer();
    let mut export: serde_json::Value = serde_json::from_slice(&package(
        false,
        publisher.as_ref(),
        AIBOM_DIGEST,
        b"invalid package signature".to_vec(),
    ))
    .unwrap();
    let signature_byte = export["signature"]["signature_bytes"][0].as_u64().unwrap() as u8;
    export["signature"]["signature_bytes"][0] = serde_json::json!(signature_byte ^ 1);
    let export = serde_json::to_vec(&export).unwrap();
    let (manifest, chunks) = create_manifest(&export, publisher.as_ref()).unwrap();
    let dir = partial_dir("bad-package-signature");
    let mut receiver =
        DiskTransferReceiver::create(&dir, manifest, "publisher", publisher.public_key()).unwrap();
    for chunk in chunks {
        receiver.accept(chunk).unwrap();
    }
    assert!(receiver
        .finalize("publisher", publisher.public_key(), AIBOM_DIGEST)
        .is_err());
    std::fs::remove_dir_all(&dir).unwrap();

    let (manifest, chunks, publisher) = disk_fixture(false, b"valid export".to_vec());
    let dir = partial_dir("bad-aibom-binding");
    let mut receiver =
        DiskTransferReceiver::create(&dir, manifest, "publisher", publisher.public_key()).unwrap();
    for chunk in chunks {
        receiver.accept(chunk).unwrap();
    }
    assert!(receiver
        .finalize("publisher", publisher.public_key(), &"00".repeat(32))
        .is_err());
    std::fs::remove_dir_all(dir).unwrap();
}
