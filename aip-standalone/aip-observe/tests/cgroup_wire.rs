//! Observe protocol 13 (ADR-019 §10): the in-event cgroup id and the cgroup
//! lifecycle kinds are inside the signed bytes, earlier records reproduce
//! theirs, and a record cannot claim an earlier version while carrying
//! later content.

use aip_crypto::{generate_ed25519_keypair, sign_ed25519};
use aip_observe::*;
use aip_types::KeyPair;

const OBSERVER: &str = "collector.cgroup-wire";
const KEY_V: u32 = 1;
const PROBE: &str = "probe-cgroup-wire";

/// The compatibility boundary, pinned with the change that owns it —
/// protocol 13 is structural attribution. A bump fails here, where the
/// person making it is working. Bumping means: changelog on the constant,
/// say what the new version adds, and either keep a verification path for
/// every version sealed in committed evidence or retire that evidence
/// explicitly (`tests/sealed_archives.rs` fails until one is done).
#[test]
fn the_protocol_version_is_thirteen_and_twelve_stays_verifiable() {
    assert_eq!(OBSERVE_PROTOCOL_VERSION, 13);
    assert_eq!(CGROUP_PROTOCOL_VERSION, 13);
    assert_eq!(VERIFIABLE_PROTOCOL_VERSIONS, [12, 13]);
    assert!(!is_verifiable_version(11) && !is_verifiable_version(14));
    // The identity tuple did not change in 13, so neither does its digest.
    assert_eq!(OBSERVED_PROCESS_IDENTITY_VERSION, 12);
}

struct Fx {
    signer: CollectorSigner,
    kp: KeyPair,
    anchors: ObserverTrustAnchors,
    probe: ProcfsProbe,
}

fn fx() -> Fx {
    let kp = generate_ed25519_keypair();
    Fx {
        signer: CollectorSigner::new(OBSERVER, KEY_V, &kp.private_key, &kp.public_key).unwrap(),
        anchors: ObserverTrustAnchors::new().trust(OBSERVER, KEY_V, &kp.public_key),
        kp,
        probe: ProcfsProbe::new(PROBE),
    }
}

fn exec_event(version: u16, seq: u64, cgroup: CgroupSample) -> KernelLifecycleEvent {
    KernelLifecycleEvent {
        version,
        probe_id: PROBE.into(),
        mechanism: SourceMechanism::SchedTracepoint,
        kind: KernelLifecycleKind::ProcessExec {
            pid: 4242,
            old_pid: 4242,
            filename: "/bin/true".into(),
        },
        cpu: 0,
        kernel_timestamp_ns: 1_000,
        probe_seq: seq,
        bound: None,
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
        cgroup,
    }
}

fn attach() -> KernelLifecycleKind {
    KernelLifecycleKind::CgroupAttach {
        hierarchy: 0,
        dst_level: 2,
        dst_cgroup_id: 9001,
        dst_path: "/aip/00112233445566778899aabbccddeeff".into(),
        pid: 4242,
        comm: "sh".into(),
        writer_pid: 77,
    }
}

/// A v13 batch carrying `events`, attested by the collector.
fn attested(f: &mut Fx, events: Vec<KernelLifecycleEvent>) -> AttestedBatch {
    let mut b = f.probe.batch([1; 16], 100, 200, vec![]);
    for (i, mut e) in events.into_iter().enumerate() {
        e.probe_seq = b.probe_seq_first + i as u64;
        b.kernel_events.push(e);
    }
    b.probe_seq_last = b.probe_seq_first + b.kernel_events.len().saturating_sub(1) as u64;
    f.signer.attest(b).unwrap()
}

/// The same batch claimed at `version` and re-signed with the real key — the
/// strongest forger: every byte is signed, only the version claim lies.
fn resigned_at(f: &Fx, mut a: AttestedBatch, version: u16) -> AttestedBatch {
    a.version = version;
    a.batch.version = version;
    for e in &mut a.batch.kernel_events {
        e.version = version;
    }
    a.attestation = sign_ed25519(&f.kp.private_key, OBSERVER, &a.signing_preimage()).unwrap();
    a
}

#[test]
fn a_sampled_cgroup_id_is_inside_the_signed_bytes() {
    let mut f = fx();
    let a = attested(
        &mut f,
        vec![exec_event(13, 0, CgroupSample::Sampled { cgroup_id: 9001 })],
    );
    assert_eq!(verify_attested_batch(&a, &f.anchors), Ok(()));

    let mut moved = a.clone();
    moved.batch.kernel_events[0].cgroup = CgroupSample::Sampled { cgroup_id: 9002 };
    assert_eq!(
        verify_attested_batch(&moved, &f.anchors),
        Err(VerifyError::PayloadHashMismatch)
    );

    let mut erased = a.clone();
    erased.batch.kernel_events[0].cgroup = CgroupSample::NotSampled;
    assert_eq!(
        verify_attested_batch(&erased, &f.anchors),
        Err(VerifyError::PayloadHashMismatch)
    );
}

#[test]
fn not_sampled_and_every_sampled_id_encode_distinctly() {
    let none = exec_event(13, 0, CgroupSample::NotSampled).canonical_bytes();
    let zero = exec_event(13, 0, CgroupSample::Sampled { cgroup_id: 0 }).canonical_bytes();
    let one = exec_event(13, 0, CgroupSample::Sampled { cgroup_id: 1 }).canonical_bytes();
    assert_ne!(none, zero, "id 0 is not 'not sampled'");
    assert_ne!(zero, one);
    assert_eq!(CgroupSample::default(), CgroupSample::NotSampled);
}

/// A v12 record encodes exactly what v12 encoded: the cgroup field is absent
/// from its bytes, so a sealed v12 signature still covers them.
#[test]
fn a_v12_event_encodes_no_cgroup_field() {
    let v12 = exec_event(12, 0, CgroupSample::NotSampled).canonical_bytes();
    let v13 = exec_event(13, 0, CgroupSample::NotSampled).canonical_bytes();
    // Same content; v13 adds exactly the one presence byte (and the
    // version field differs).
    assert_eq!(v13.len(), v12.len() + 1);
}

/// The forgery the version gate exists for: content the v12 encoding cannot
/// carry, claimed as v12 and validly signed. Its cgroup id would sit outside
/// the signed bytes; it is refused. The control shows v12 itself is not
/// what is refused.
#[test]
fn a_v12_record_carrying_v13_content_is_refused() {
    let mut f = fx();
    let sampled = attested(
        &mut f,
        vec![exec_event(13, 0, CgroupSample::Sampled { cgroup_id: 9001 })],
    );
    assert_eq!(
        verify_attested_batch(&resigned_at(&f, sampled, 12), &f.anchors),
        Err(VerifyError::ContentNotInVersion(12))
    );

    let mut g = fx();
    let kind = attested(
        &mut g,
        vec![{
            let mut e = exec_event(13, 0, CgroupSample::NotSampled);
            e.kind = attach();
            e
        }],
    );
    assert_eq!(
        verify_attested_batch(&resigned_at(&g, kind, 12), &g.anchors),
        Err(VerifyError::ContentNotInVersion(12))
    );

    let mut h = fx();
    let plain = attested(&mut h, vec![exec_event(13, 0, CgroupSample::NotSampled)]);
    assert_eq!(
        verify_attested_batch(&resigned_at(&h, plain, 12), &h.anchors),
        Ok(())
    );
}

#[test]
fn a_v12_batch_declaring_exec_permission_is_refused() {
    let mut f = fx();
    let a = attested(&mut f, vec![]);
    let mut v12 = resigned_at(&f, a, 12);
    v12.batch
        .active_mechanisms
        .push(SourceMechanism::ExecPermission);
    v12.attestation = sign_ed25519(&f.kp.private_key, OBSERVER, &v12.signing_preimage()).unwrap();
    assert_eq!(
        verify_attested_batch(&v12, &f.anchors),
        Err(VerifyError::ContentNotInVersion(12))
    );
}

/// Mixed versions inside one batch are refused: one record, one encoding.
#[test]
fn a_batch_mixing_event_versions_is_refused() {
    let mut f = fx();
    let a = attested(&mut f, vec![exec_event(13, 0, CgroupSample::NotSampled)]);
    let mut mixed = a.clone();
    mixed.batch.kernel_events[0].version = 12;
    mixed.attestation =
        sign_ed25519(&f.kp.private_key, OBSERVER, &mixed.signing_preimage()).unwrap();
    assert_eq!(
        verify_attested_batch(&mixed, &f.anchors),
        Err(VerifyError::ContentNotInVersion(13))
    );
}

/// Every field of every new kind is in the digest, and the kinds cannot be
/// confused for one another.
#[test]
fn every_cgroup_kind_field_is_signed_and_the_kinds_are_distinct() {
    let digest = |k: KernelLifecycleKind| {
        let mut e = exec_event(13, 0, CgroupSample::NotSampled);
        e.kind = k;
        e.digest()
    };
    let base = attach();
    let KernelLifecycleKind::CgroupAttach { .. } = base else {
        unreachable!()
    };
    type Edit = fn(&mut KernelLifecycleKind);
    let edits: [Edit; 7] = [
        |k| {
            if let KernelLifecycleKind::CgroupAttach { hierarchy, .. } = k {
                *hierarchy += 1
            }
        },
        |k| {
            if let KernelLifecycleKind::CgroupAttach { dst_level, .. } = k {
                *dst_level += 1
            }
        },
        |k| {
            if let KernelLifecycleKind::CgroupAttach { dst_cgroup_id, .. } = k {
                *dst_cgroup_id += 1
            }
        },
        |k| {
            if let KernelLifecycleKind::CgroupAttach { dst_path, .. } = k {
                dst_path.push('x')
            }
        },
        |k| {
            if let KernelLifecycleKind::CgroupAttach { pid, .. } = k {
                *pid += 1
            }
        },
        |k| {
            if let KernelLifecycleKind::CgroupAttach { comm, .. } = k {
                comm.push('x')
            }
        },
        |k| {
            if let KernelLifecycleKind::CgroupAttach { writer_pid, .. } = k {
                *writer_pid += 1
            }
        },
    ];
    for (i, edit) in edits.iter().enumerate() {
        let mut k = base.clone();
        edit(&mut k);
        assert_ne!(
            digest(k),
            digest(base.clone()),
            "attach field {i} not signed"
        );
    }
    let created = KernelLifecycleKind::CgroupCreated {
        hierarchy: 0,
        level: 2,
        cgroup_id: 9001,
        path: "/aip/x".into(),
        creator_pid: 77,
    };
    let removed = KernelLifecycleKind::CgroupRemoved {
        hierarchy: 0,
        level: 2,
        cgroup_id: 9001,
        path: "/aip/x".into(),
        remover_pid: 77,
    };
    assert_ne!(
        digest(created.clone()),
        digest(removed.clone()),
        "mkdir and rmdir are distinct"
    );
    assert_eq!(created.subject_pid(), Some(77));
    assert_eq!(removed.subject_pid(), Some(77));
    assert_eq!(
        base.subject_pid(),
        Some(4242),
        "a migration is about the task moved"
    );
}
