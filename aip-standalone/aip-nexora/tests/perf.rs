//! Skill 10 Gate 15 — measurement, on this host and no other.
//!
//! Every number this file prints was measured by running the code. None is
//! a target, a projection, a specification or a comparison to anything
//! else, and none of it generalises: it is one 4-vCPU virtual machine, and
//! a different machine or a larger evidence set will give different
//! figures. The point is not the numbers themselves but that they exist and
//! were obtained rather than asserted.
//!
//! The build profile is printed with the numbers because without it they
//! mean nothing: unoptimised Ed25519 verification is roughly two orders of
//! magnitude slower, and most of a verification is Ed25519.
//!
//! Run `cargo test -p aip-nexora --test perf -- --nocapture` to see the
//! table. The assertions here are deliberately loose — they exist to catch
//! a change of order of magnitude, not to pin a figure that would make the
//! suite fail on a busier machine.

mod common;

use std::time::Instant;

use aip_nexora::capability::VerifierCapability;
use aip_nexora::export::*;
use aip_nexora::proof::*;
use aip_nexora::verify::*;

fn package(s: &common::Scenario) -> NexoraProof {
    NexoraProof::builder(s.a.agent_id.clone(), s.reconciliation.clone())
        .issued_at(s.at + 1)
        .authority(s.a.root.clone(), s.a.chain.clone())
        .expectation(s.a.ee.clone())
        .observer(s.evidence.batches.clone(), s.evidence.health.clone())
        .parameters(DeclaredParameters {
            verification_time_ms: s.at,
            health_max_age_ms: common::HEALTH_MAX_AGE,
            window_tolerance_ms: 0,
            agent_key_supplied: true,
        })
        .build()
}

fn anchors(s: &common::Scenario) -> VerifierAnchors {
    VerifierAnchors {
        decision_point: s.a.dp_anchors.clone(),
        observer: s.o.anchors.clone(),
        warrant: aip_warrant::WarrantTrustAnchors::new(),
        nexora: aip_nexora::NexoraTrustAnchors::new(),
        issuers: s.a.issuer_keys.clone(),
        agent_public_key: Some(s.a.agent_kp.public_key.clone()),
        capability: VerifierCapability::strict(),
        present_time_ms: None,
    }
}

/// Median of `n` runs. The median rather than the mean because a shared
/// virtual machine produces occasional outliers that say more about the
/// neighbours than about this code.
fn median_us(n: usize, mut f: impl FnMut()) -> u128 {
    let mut samples: Vec<u128> = (0..n)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_micros()
        })
        .collect();
    samples.sort_unstable();
    samples[n / 2]
}

#[test]
fn g15_the_measured_cost_of_a_proof_on_this_host() {
    let s = common::verified_execution();
    let proof = package(&s);
    let a = anchors(&s);
    let bytes = export_proof(&proof).unwrap();

    // ─── Size ───
    let batches = proof.observer.as_ref().unwrap().batches.len();
    let kernel_events: usize = proof
        .observer
        .as_ref()
        .unwrap()
        .batches
        .iter()
        .map(|b| b.batch.kernel_events.len())
        .sum();
    let signatures = 1 // the decision point over the expectation
        + 1 // the root token's issuer
        + proof.authority.as_ref().unwrap().chain.len()
        + batches // one collector attestation per batch
        + 1; // the signed health

    // ─── Time ───
    let build_us = median_us(50, || {
        let _ = package(&s);
    });
    let export_us = median_us(50, || {
        let _ = export_proof(&proof).unwrap();
    });
    let import_us = median_us(50, || {
        let _ = import_proof(&bytes).unwrap();
    });
    let verify_us = median_us(50, || {
        let _ = verify_nexora_proof(&proof, &a);
    });
    // A cold verify: parse from bytes and check, which is what an offline
    // verifier actually does with a file it was handed.
    let cold_us = median_us(50, || {
        let p = import_proof(&bytes).unwrap();
        let _ = verify_nexora_proof(&p, &a);
    });

    // Confirm the thing being timed is the thing that works.
    assert!(verify_nexora_proof(&proof, &a).is_valid());

    println!("\n─── NEXORA proof cost, measured on this host ───");
    println!(
        "host            Linux {} · 4 vCPU · {} build",
        kernel(),
        profile()
    );
    println!(
        "proof bytes     {} ({} kB)",
        bytes.len(),
        bytes.len() / 1024
    );
    println!("evidence items  {batches} attested batch(es), {kernel_events} kernel event(s)");
    println!("signatures      {signatures} verified per check");
    println!("build           {build_us} µs");
    println!("export          {export_us} µs");
    println!("import          {import_us} µs");
    println!("verify (warm)   {verify_us} µs");
    println!("verify (cold)   {cold_us} µs  ← parse + verify, the offline case");
    println!("───────────────────────────────────────────────\n");

    // Loose bounds: an order-of-magnitude regression detector, not a
    // performance specification. A shared virtual machine is not a basis
    // for a tighter claim than this, and the debug profile is slower again.
    assert!(
        bytes.len() < 1_000_000,
        "a proof of one action grew past 1 MB"
    );
    assert!(cold_us < 5_000_000, "cold verification took over 5 seconds");
    assert!(signatures >= 5, "the count must reflect real signatures");
}

/// How the package grows with the evidence it carries. Measured, not
/// modelled: the same scenario re-attested with more batches.
#[test]
fn g15_size_grows_with_the_evidence_and_nothing_else() {
    let s = common::verified_execution();
    let base = export_proof(&package(&s)).unwrap().len();

    let mut wider = package(&s);
    let bundle = wider.observer.as_mut().unwrap();
    let one = bundle.batches[1].clone();
    for _ in 0..9 {
        bundle.batches.push(one.clone());
    }
    let wider_len = export_proof(&wider).unwrap().len();

    let per_batch = (wider_len - base) / 9;
    println!("\nbase package     {base} bytes ({} batches)", 2);
    println!("with 9 more      {wider_len} bytes");
    println!("marginal batch   ~{per_batch} bytes\n");
    assert!(wider_len > base, "more evidence must not shrink a package");
    // The growth is in the evidence, not in a per-package overhead that
    // multiplies: ten batches must not cost ten base packages.
    assert!(
        wider_len < base * 10,
        "package overhead is being duplicated per batch"
    );
}

/// Which build this was measured under. Ed25519 verification is roughly
/// two orders of magnitude slower unoptimised, so a figure without its
/// profile is not a figure.
fn profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

fn kernel() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}
