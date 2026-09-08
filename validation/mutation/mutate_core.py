#!/usr/bin/env python3
"""Mutation harness for the authoritative reconciler and verifier.

The 27-skill conformance run (docs/SKILL_CONFORMANCE_27_FULL_RUN.md, §11.1)
recorded this as the highest-priority remaining assurance gap: aip-reconcile
and aip-nexora are the sole authorities for their questions, they carry 351
tests between them, and nothing established that those tests would fail if the
logic underneath them were broken. This harness establishes it.

METHODOLOGY — the same one Skills 11-27 used
--------------------------------------------
A mutation result is only interpretable once the mutation is proven to have
been active. For every mutation, in order:

  1. the `old` fragment is found in the file, and found EXACTLY ONCE;
  2. the file is rewritten and its SHA-256 is confirmed to have changed;
  3. the crate's test targets are COMPILED — a mutation that does not build
     was never active, and is recorded as a harness defect, not a kill;
  4. the targeted test set is run;
  5. at least one test must FAIL, otherwise the mutation SURVIVED;
  6. the file is restored from the bytes read in step 1, and the restored
     SHA-256 is confirmed equal to the original.

Step 6 runs in a `finally`, so an interrupted run does not leave a mutated
tree. The final byte-identity check over every touched file is printed at the
end and is part of the result.

WHAT IS AND IS NOT A LEGITIMATE TARGET
--------------------------------------
Every mutation here inverts, removes, or downgrades ONE security or
correctness invariant that is observable from outside the crate. Formatting,
logging, unreachable branches and internal representation choices are not
targets: killing those proves nothing about the security of the system, and
padding the count with them would make the result dishonest.

A mutation that SURVIVES is reported as a survivor. It is never rescoped,
never reclassified, and never removed from the matrix.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
RECONCILE = REPO / "aip-standalone/aip-reconcile/src/reconcile.rs"
RESULT = REPO / "aip-standalone/aip-reconcile/src/result.rs"
COMMITMENT = REPO / "aip-standalone/aip-nexora/src/commitment.rs"
VERIFY = REPO / "aip-standalone/aip-nexora/src/verify.rs"

# ── The matrix ────────────────────────────────────────────────────────────
# `invariant` states the externally observable property the mutation breaks.
MUTATIONS = [
    # ═══ aip-reconcile ═══════════════════════════════════════════════════
    {
        "id": "R-01",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "a structurally or cryptographically invalid expectation cannot yield a verdict",
        "old": "        return Err(draft.cannot_prove(reason));\n    }\n    let window = CoverageWindow {",
        "new": "        let _ = reason;\n    }\n    let window = CoverageWindow {",
    },
    {
        "id": "R-02",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "missing observer evidence is CANNOT_PROVE, never a verdict (absence is not evidence)",
        "old": "        return Err(draft.cannot_prove(ReasonCode::NoObserverEvidence));",
        "new": "        return Err(draft.finish(\n            ReconciliationResult::VerifiedExecution,\n            EvidenceStrength::Attested,\n            ReasonCode::NoObserverEvidence,\n        ));",
    },
    {
        "id": "R-03",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "an invalid observer signature is an integrity failure, not mere inability to prove",
        "old": "        | VerifyError::SignatureInvalid => {\n            ObserverCheck::IntegrityFailure(ReasonCode::ObserverSignatureInvalid)\n        }",
        "new": "        | VerifyError::SignatureInvalid => {\n            ObserverCheck::CannotProve(ReasonCode::ObserverSignatureInvalid)\n        }",
    },
    {
        "id": "R-04",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "batches from a second observer cannot be mixed into one observer's chain",
        "old": "        if b.observer_id != health.observer_id {\n            return ObserverCheck::CannotProve(ReasonCode::MixedObservers);\n        }",
        "new": "        if false {\n            return ObserverCheck::CannotProve(ReasonCode::MixedObservers);\n        }",
    },
    {
        "id": "R-05",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "two validly signed batches at one sequence are a proven observer fork",
        "old": "    for w in batches.windows(2) {\n        if w[0].sequence == w[1].sequence {\n            return ObserverCheck::IntegrityFailure(ReasonCode::ObserverChainBroken);\n        }\n    }",
        "new": "    for w in batches.windows(2) {\n        if false && w[0].sequence == w[1].sequence {\n            return ObserverCheck::IntegrityFailure(ReasonCode::ObserverChainBroken);\n        }\n    }",
    },
    {
        "id": "R-06",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "a gap in the batch sequence is an incomplete observation set",
        "old": "        if w[1].sequence != w[0].sequence + 1 {\n            return ObserverCheck::CannotProve(ReasonCode::ObservationSetIncomplete);\n        }",
        "new": "        if false {\n            return ObserverCheck::CannotProve(ReasonCode::ObservationSetIncomplete);\n        }",
    },
    {
        "id": "R-07",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "a broken prev_head linkage is an observer chain break",
        "old": "        if w[1].prev_head != w[0].head() {\n            return ObserverCheck::IntegrityFailure(ReasonCode::ObserverChainBroken);\n        }",
        "new": "        if false {\n            return ObserverCheck::IntegrityFailure(ReasonCode::ObserverChainBroken);\n        }",
    },
    {
        "id": "R-08",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "batches withheld from the tail of the chain are detectable against the health record",
        "old": "        if last.sequence != health.sequence || last.head() != health.head {\n            return ObserverCheck::CannotProve(ReasonCode::ObservationSetIncomplete);\n        }",
        "new": "        if false {\n            return ObserverCheck::CannotProve(ReasonCode::ObservationSetIncomplete);\n        }",
    },
    {
        "id": "R-09",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "a replayed batch is recorded as replay, not silently deduplicated",
        "old": "        if seen.contains(&key) {\n            draft.replay_detected = true;\n            continue;\n        }",
        "new": "        if seen.contains(&key) {\n            continue;\n        }",
    },
    {
        "id": "R-10",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "I10 — an observer anchored to the agent's own key is not independent",
        "old": "            return ObserverCheck::CannotProve(ReasonCode::ObserverKeyIsAgentKey);\n        }\n    }\n    draft.evidence.push(EvidenceRef::Health {",
        "new": "            ()\n        }\n    }\n    draft.evidence.push(EvidenceRef::Health {",
    },
    {
        "id": "R-11",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "reconcile_expectation: a quarantined observer yields SensorIntegrityFailure, never a positive verdict",
        "old": "    let state = obs.health.state;\n    match state {\n        ObserverState::Quarantined => {\n            return draft.finish(\n                ReconciliationResult::SensorIntegrityFailure,\n                EvidenceStrength::Attested,\n                ReasonCode::ObserverQuarantined,\n            )\n        }",
        "new": "    let state = obs.health.state;\n    match state {\n        ObserverState::Quarantined => {}",
    },
    {
        "id": "R-11b",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "reconcile_lineage: a quarantined observer yields SensorIntegrityFailure, never a positive verdict",
        "old": "    // Observer state gates lineage exactly as it gates actions.\n    match obs.health.state {\n        ObserverState::Quarantined => {\n            return draft.finish(\n                ReconciliationResult::SensorIntegrityFailure,\n                EvidenceStrength::Attested,\n                ReasonCode::ObserverQuarantined,\n            )\n        }",
        "new": "    // Observer state gates lineage exactly as it gates actions.\n    match obs.health.state {\n        ObserverState::Quarantined => {}",
    },
    {
        "id": "R-12",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "reconcile_expectation: an observer whose integrity is unknown cannot support a positive verdict",
        "old": "    let state = obs.health.state;\n    match state {",
        "new": "    let state = obs.health.state;\n    #[allow(unreachable_patterns)]\n    match state {\n        ObserverState::IntegrityUnknown => {}",
    },
    {
        "id": "R-12b",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "reconcile_lineage: an observer whose integrity is unknown cannot support a positive verdict",
        "old": "    // Observer state gates lineage exactly as it gates actions.\n    match obs.health.state {",
        "new": "    // Observer state gates lineage exactly as it gates actions.\n    #[allow(unreachable_patterns)]\n    match obs.health.state {\n        ObserverState::IntegrityUnknown => {}",
    },
    {
        "id": "R-13",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "reconcile_expectation: a degraded observer cannot support a positive verdict",
        "old": "    // Observer state gates every positive statement.\n    let state = obs.health.state;",
        "new": "    // Observer state gates every positive statement.\n    #[allow(unreachable_patterns)]\n    let state = match obs.health.state {\n        ObserverState::Degraded => ObserverState::Active,\n        s => s,\n    };\n    let _unused = obs.health.state;",
    },
    {
        "id": "R-13b",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "reconcile_lineage: a degraded observer cannot support a positive verdict",
        "old": "    // Observer state gates lineage exactly as it gates actions.\n    match obs.health.state {\n        ObserverState::Quarantined => {",
        "new": "    // Observer state gates lineage exactly as it gates actions.\n    match (if obs.health.state == ObserverState::Degraded { ObserverState::Active } else { obs.health.state }) {\n        ObserverState::Quarantined => {",
    },
    {
        "id": "R-14",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "matching and divergent observations together are ambiguous, not a match",
        "old": "        (m, d, _, _) => IdentityComparison::Ambiguous {\n            matching: m as u32,\n            divergent: d as u32,\n        },",
        "new": "        (m, _d, _, _) => IdentityComparison::Match {\n            observations: m as u32,\n        },",
    },
    {
        "id": "R-15",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "ambiguous identity is CANNOT_PROVE",
        "old": "        IdentityComparison::Ambiguous { .. } => {\n            draft.cannot_prove(ReasonCode::AmbiguousObservations)\n        }",
        "new": "        IdentityComparison::Ambiguous { .. } => draft.finish(\n            ReconciliationResult::VerifiedExecution,\n            EvidenceStrength::Attested,\n            ReasonCode::AmbiguousObservations,\n        ),",
    },
    {
        "id": "R-16",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "a stale health record settles nothing about the window",
        "old": "        return Err(draft.cannot_prove(ReasonCode::HealthStale));",
        "new": "        let _ = ReasonCode::HealthStale;",
    },
    {
        "id": "R-17",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "a forward-set collector clock cannot saturate staleness to age zero",
        "old": "        return Err(draft.cannot_prove(ReasonCode::HealthNotYetEmitted));",
        "new": "        let _ = ReasonCode::HealthNotYetEmitted;",
    },
    {
        "id": "R-18",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "reconcile_expectation: an Open-policy (unverified-provenance) mechanism label cannot support a match",
        "old": "            if !matches!(outcome, ActionOutcome::None)\n                && obs.health.probe_policy == ProbePolicy::Open\n            {",
        "new": "            if false\n                && obs.health.probe_policy == ProbePolicy::Open\n            {",
    },
    {
        "id": "R-19",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "action evidence that does not match the expectation is not a verified execution",
        "old": "                ActionOutcome::Mismatch { mechanism, kind } => {\n                    draft.action = ActionComparison::mismatched(mechanism, kind);\n                    draft.cannot_prove(ReasonCode::ActionEvidenceDoesNotMatch)\n                }",
        "new": "                ActionOutcome::Mismatch { mechanism, kind } => {\n                    draft.action = ActionComparison::mismatched(mechanism, kind);\n                    draft.finish(\n                        ReconciliationResult::VerifiedExecution,\n                        EvidenceStrength::Attested,\n                        ReasonCode::ActionEvidenceDoesNotMatch,\n                    )\n                }",
    },
    {
        "id": "R-20",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "action evidence preceding its authorization does not verify the execution",
        "old": "                ActionOutcome::Precedes => {\n                    draft.temporal = TemporalComparison::BeforeWindow;\n                    draft.cannot_prove(ReasonCode::ActionPrecedesAuthorization)\n                }",
        "new": "                ActionOutcome::Precedes => {\n                    draft.temporal = TemporalComparison::BeforeWindow;\n                    draft.finish(\n                        ReconciliationResult::VerifiedExecution,\n                        EvidenceStrength::Attested,\n                        ReasonCode::ActionPrecedesAuthorization,\n                    )\n                }",
    },
    {
        "id": "R-21",
        "pkg": "aip-reconcile",
        "file": RESULT,
        "invariant": "a record read back from bytes is not engine-produced, however faithful (B-9 seal)",
        "old": "    pub fn is_engine_produced(&self) -> bool {",
        "new": "    pub fn is_engine_produced(&self) -> bool {\n        if true {\n            return true;\n        }",
    },
    # ═══ aip-nexora ══════════════════════════════════════════════════════
    {
        "id": "N-01",
        "pkg": "aip-nexora",
        "file": COMMITMENT,
        "invariant": "an anchor is bound to (signer_id, key_version): a head naming another key version is not verified by this key",
        "old": "    pub fn get(&self, signer_id: &str, key_version: u32) -> Option<&[u8]> {\n        self.keys\n            .get(&(signer_id.to_string(), key_version))\n            .map(Vec::as_slice)\n    }",
        "new": "    pub fn get(&self, signer_id: &str, key_version: u32) -> Option<&[u8]> {\n        let _ = key_version;\n        self.keys\n            .iter()\n            .find(|((id, _), _)| id == signer_id)\n            .map(|(_, k)| k.as_slice())\n    }",
    },
    {
        "id": "N-02",
        "pkg": "aip-nexora",
        "file": COMMITMENT,
        "invariant": "the signature's signer_id must be the head's signer_id",
        "old": "    if head.signature.signer_id != head.signer_id {\n        return Err(NexoraError::SignerMismatch);\n    }",
        "new": "    if false {\n        return Err(NexoraError::SignerMismatch);\n    }",
    },
    {
        "id": "N-03",
        "pkg": "aip-nexora",
        "file": COMMITMENT,
        "invariant": "the signed payload hash must be the hash of the head's own preimage",
        "old": "    if head.signature.payload_hash != sha256(&head.signing_preimage()) {\n        return Err(NexoraError::PayloadHashMismatch);\n    }",
        "new": "    if false {\n        return Err(NexoraError::PayloadHashMismatch);\n    }",
    },
    {
        "id": "N-04",
        "pkg": "aip-nexora",
        "file": COMMITMENT,
        "invariant": "a head whose Ed25519 signature does not verify is refused",
        "old": "    match verify_ed25519(key, &head.signature) {\n        Ok(true) => Ok(()),\n        Ok(false) => Err(NexoraError::SignatureInvalid),",
        "new": "    match verify_ed25519(key, &head.signature) {\n        Ok(true) => Ok(()),\n        Ok(false) => Ok(()),",
    },
    {
        "id": "N-05",
        "pkg": "aip-nexora",
        "file": COMMITMENT,
        "invariant": "a head declaring an unsupported NEXORA version is refused",
        "old": "    if head.version != NEXORA_VERSION {\n        return Err(NexoraError::UnsupportedVersion(head.version));\n    }",
        "new": "    if false {\n        return Err(NexoraError::UnsupportedVersion(head.version));\n    }",
    },
    {
        "id": "N-06",
        "pkg": "aip-nexora",
        "file": COMMITMENT,
        "invariant": "a proof must name the same log as the head it carries",
        "old": "    if proof.log_id != proof.head.log_id {\n        return Err(NexoraError::LogMismatch {",
        "new": "    if false {\n        return Err(NexoraError::LogMismatch {",
    },
    {
        "id": "N-07",
        "pkg": "aip-nexora",
        "file": COMMITMENT,
        "invariant": "the inclusion proof's tree size must be the head's size",
        "old": "    if proof.inclusion.size != proof.head.size {\n        return Err(NexoraError::SizeMismatch {",
        "new": "    if false {\n        return Err(NexoraError::SizeMismatch {",
    },
    {
        "id": "N-08",
        "pkg": "aip-nexora",
        "file": COMMITMENT,
        "invariant": "the record must actually be included under the head's committed root",
        "old": "    if !verify_inclusion(&leaf, &proof.inclusion, &proof.head.root) {\n        return Err(NexoraError::LeafNotIncluded);\n    }",
        "new": "    if false {\n        return Err(NexoraError::LeafNotIncluded);\n    }",
    },
    {
        "id": "N-09",
        "pkg": "aip-nexora",
        "file": COMMITMENT,
        "invariant": "a head tracker never accepts a rollback to a smaller tree",
        "old": "        if head.size < last.size {\n            return Err(NexoraError::Rollback {",
        "new": "        if false {\n            return Err(NexoraError::Rollback {",
    },
    {
        "id": "N-10",
        "pkg": "aip-nexora",
        "file": COMMITMENT,
        "invariant": "two distinct heads at one size are a fork",
        "old": "        if head.size == last.size {\n            return Err(NexoraError::Fork { size: head.size });\n        }",
        "new": "        if false {\n            return Err(NexoraError::Fork { size: head.size });\n        }",
    },
    {
        "id": "N-11",
        "pkg": "aip-nexora",
        "file": COMMITMENT,
        "invariant": "an extension without a valid consistency proof is refused",
        "old": "        if proof.old_size != last.size\n            || proof.new_size != head.size\n            || !verify_consistency(&last.root, &head.root, proof)\n        {\n            return Err(NexoraError::ConsistencyInvalid);\n        }",
        "new": "        if false {\n            return Err(NexoraError::ConsistencyInvalid);\n        }",
    },
    {
        "id": "N-12",
        "pkg": "aip-nexora",
        "file": VERIFY,
        "invariant": "a claimed verdict that the verifier cannot re-derive is refused (the package's own claim is never trusted)",
        "old": "            if claimed != got && first_failure.is_none() {",
        "new": "            if false && claimed != got && first_failure.is_none() {",
    },
    {
        "id": "N-13",
        "pkg": "aip-nexora",
        "file": VERIFY,
        "invariant": "a refused package establishes no result and no strength",
        "old": "        v.result = None;\n        v.strength = None;\n    }\n    v\n}",
        "new": "    }\n    v\n}",
    },
    {
        "id": "N-14",
        "pkg": "aip-nexora",
        "file": VERIFY,
        "invariant": "a structurally faulty package is refused before any component is credited",
        "old": "    if let Some(f) = proof.structural_faults().into_iter().next() {\n        v.verdict = ProofVerdict::Invalid(InvalidReason::Structural(f));\n        return v;\n    }",
        "new": "    if let Some(f) = proof.structural_faults().into_iter().next() {\n        let _ = f;\n    }",
    },
    {
        "id": "N-15",
        "pkg": "aip-nexora",
        "file": VERIFY,
        "invariant": "a package whose components are not bound to one another is refused",
        "old": "    if let Some(f) = proof.binding_faults().into_iter().next() {\n        v.verdict = ProofVerdict::Invalid(InvalidReason::Binding(f));\n        return v;\n    }",
        "new": "    if let Some(f) = proof.binding_faults().into_iter().next() {\n        let _ = f;\n    }",
    },
    {
        "id": "N-16",
        "pkg": "aip-nexora",
        "file": VERIFY,
        "invariant": "a package declaring a version this verifier does not understand is refused",
        "old": "    if !anchors.capability.understands(proof.version) {\n        v.verdict = ProofVerdict::Invalid(InvalidReason::UnsupportedVersion(proof.version));\n        return v;\n    }",
        "new": "    if false {\n        v.verdict = ProofVerdict::Invalid(InvalidReason::UnsupportedVersion(proof.version));\n        return v;\n    }",
    },
    {
        "id": "N-17",
        "pkg": "aip-nexora",
        "file": VERIFY,
        "invariant": "a carried-but-unreached component is Unverifiable, never Absent (absence of evidence is not evidence of absence)",
        "old": "    let unreached = |carried: bool| {\n        if carried {\n            ComponentVerdict::Unverifiable(NOT_REACHED.to_string())\n        } else {\n            ComponentVerdict::Absent\n        }\n    };",
        "new": "    let unreached = |carried: bool| {\n        let _ = carried;\n        ComponentVerdict::Absent\n    };",
    },
    {
        "id": "N-18",
        "pkg": "aip-nexora",
        "file": VERIFY,
        "invariant": "independence is what THIS verifier checked, not what the package asserts (Defect #5)",
        "old": "        independence: if proof.parameters.agent_key_supplied && anchors.agent_public_key.is_some() {",
        "new": "        independence: if proof.parameters.agent_key_supplied {",
    },
    {
        "id": "N-19",
        "pkg": "aip-nexora",
        "file": VERIFY,
        "invariant": "a verified continuity break is reported as discontinuous, never softened",
        "old": "                v.continuity_standing = ContinuityStanding::Discontinuous;",
        "new": "                v.continuity_standing = ContinuityStanding::Continuous;",
    },
    {
        "id": "N-20",
        "pkg": "aip-nexora",
        "file": VERIFY,
        "invariant": "a declared parameter beyond the verifier's own bound is refused, not silently accepted",
        "old": "    let max = anchors.capability.health_age_bound();\n    if proof.parameters.health_max_age_ms > max {",
        "new": "    let max = anchors.capability.health_age_bound();\n    if false && proof.parameters.health_max_age_ms > max {",
    },
    {
        "id": "N-21",
        "pkg": "aip-nexora",
        "file": VERIFY,
        "invariant": "a verifier that bounds reconciliation age but holds no clock refuses rather than skipping the check",
        "old": "        let age = match anchors.present_time_ms {\n            Some(now) => now.saturating_sub(declared),\n            None => u64::MAX,\n        };",
        "new": "        let age = match anchors.present_time_ms {\n            Some(now) => now.saturating_sub(declared),\n            None => 0,\n        };",
    },
    {
        "id": "N-22",
        "pkg": "aip-nexora",
        "file": VERIFY,
        "invariant": "an observer anchored to the agent's own key is not independent (I10, verifier side)",
        "old": "                        && !agent_key.is_empty()\n                    {\n                        fail(",
        "new": "                        && agent_key.is_empty()\n                    {\n                        fail(",
    },
]


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run(cmd, cwd=REPO):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def targeted(pkg, extra=None):
    cmd = ["cargo", "test", "-p", pkg]
    if extra:
        cmd += extra
    return cmd


def main():
    only = sys.argv[1:] or None
    results = []
    originals = {}
    for m in MUTATIONS:
        originals.setdefault(m["file"], m["file"].read_bytes())

    try:
        for m in MUTATIONS:
            if only and m["id"] not in only:
                continue
            f = m["file"]
            src = originals[f].decode()
            before = hashlib.sha256(originals[f]).hexdigest()

            occurrences = src.count(m["old"])
            rec = {
                "id": m["id"],
                "package": m["pkg"],
                "file": str(f.relative_to(REPO)),
                "invariant": m["invariant"],
                "fragment_occurrences": occurrences,
                "patch_applied": False,
                "compiled": False,
                "sha256_before": before[:16],
                "sha256_after": None,
                "killed_by": [],
                "result": None,
            }
            if occurrences != 1:
                rec["result"] = "HARNESS_DEFECT_FRAGMENT_NOT_UNIQUE"
                results.append(rec)
                print(f"{m['id']}: FRAGMENT NOT UNIQUE ({occurrences}) — not interpretable")
                continue

            try:
                f.write_text(src.replace(m["old"], m["new"], 1))
                after = sha(f)
                rec["sha256_after"] = after[:16]
                if after == before:
                    rec["result"] = "HARNESS_DEFECT_NO_CHANGE"
                    results.append(rec)
                    print(f"{m['id']}: FILE UNCHANGED — not interpretable")
                    continue
                rec["patch_applied"] = True

                build = run(["cargo", "build", "-p", m["pkg"], "--tests"])
                if build.returncode != 0:
                    rec["result"] = "HARNESS_DEFECT_DOES_NOT_COMPILE"
                    rec["compile_error"] = build.stderr[-1200:]
                    results.append(rec)
                    print(f"{m['id']}: DOES NOT COMPILE — not interpretable")
                    continue
                rec["compiled"] = True

                out = run(targeted(m["pkg"], ["--no-fail-fast"]))
                failing = [
                    ln.split()[1]
                    for ln in out.stdout.splitlines()
                    if ln.startswith("test ") and ln.rstrip().endswith("FAILED")
                ]
                rec["killed_by"] = failing[:12]
                rec["failing_test_count"] = len(failing)
                rec["result"] = "KILLED" if failing else "SURVIVED"
                print(
                    f"{m['id']}: {rec['result']} "
                    f"({len(failing)} failing) — {m['invariant'][:60]}"
                )
                results.append(rec)
            finally:
                f.write_bytes(originals[f])
                assert sha(f) == before, f"restore failed for {f}"
    finally:
        for f, b in originals.items():
            f.write_bytes(b)

    restored = {str(f.relative_to(REPO)): sha(f) == hashlib.sha256(b).hexdigest()
                for f, b in originals.items()}
    survivors = [r["id"] for r in results if r["result"] == "SURVIVED"]
    defects = [r["id"] for r in results if str(r["result"]).startswith("HARNESS_DEFECT")]
    killed = [r["id"] for r in results if r["result"] == "KILLED"]
    doc = {
        "harness": "validation/mutation/mutate_core.py",
        "targets": ["aip-reconcile", "aip-nexora"],
        "total": len(results),
        "killed": len(killed),
        "survivors": survivors,
        "harness_defects": defects,
        "all_files_restored_byte_identical": all(restored.values()),
        "restored": restored,
        "mutations": results,
    }
    outp = REPO / "validation/mutation/CORE_MUTATION_RESULTS.json"
    # A filtered run updates the entries it re-ran and leaves the rest, so a
    # targeted re-run after adding a regression test produces one complete
    # artifact rather than a partial one that looks like a shrunken matrix.
    if only and outp.exists():
        prev = json.loads(outp.read_text())
        by_id = {r["id"]: r for r in prev["mutations"]}
        for r in results:
            by_id[r["id"]] = r
        order = [m["id"] for m in MUTATIONS]
        merged = [by_id[i] for i in order if i in by_id]
        doc["mutations"] = merged
        doc["total"] = len(merged)
        doc["killed"] = sum(1 for r in merged if r["result"] == "KILLED")
        doc["survivors"] = [r["id"] for r in merged if r["result"] == "SURVIVED"]
        doc["harness_defects"] = [
            r["id"] for r in merged if str(r["result"]).startswith("HARNESS_DEFECT")
        ]
        doc["reran_in_last_pass"] = sorted(only)
    outp.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"\nTOTAL {len(results)}  KILLED {len(killed)}  "
          f"SURVIVORS {len(survivors)}  DEFECTS {len(defects)}")
    print(f"files restored byte-identical: {all(restored.values())}")
    print(f"-> {outp.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
