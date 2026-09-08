#!/usr/bin/env python3
"""Mutation matrix for `reconcile_observation`, the third reconciliation entry point.

`docs/RECONCILER_VERIFIER_MUTATION_ASSURANCE.md` §9.2 recorded this as the
largest gap left by the previous milestone:

    Of the three public entry points, the expectation path carries 18
    mutations and the lineage path 3; `reconcile_observation` carries none of
    its own. … Given that R-11b and R-12b were both found on the *lineage*
    path for exactly this reason — an invariant covered at one entry point and
    unguarded at another — the same failure is likely here.

This matrix tests that prediction. The forensic machinery is imported from
`mutate_core.py` rather than reimplemented, so the four proof steps — unique
fragment, changed digest, successful compile, restored bytes — cannot drift
between one matrix and another.

SITE-SPECIFICITY IS THE POINT
-----------------------------
Every fragment below is unique to `reconcile_observation`. Where an invariant
is also stated on the expectation or lineage path, mutating the shared helper
would prove nothing about *this* entry point: the expectation-path test would
kill it and the asymmetry would stay hidden. That is precisely how R-11b and
R-12b escaped the first milestone, and the whole reason this matrix exists.
"""
import sys
import importlib.util
import pathlib

_HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("mutate_core", _HERE / "mutate_core.py")
_core = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_core)

REPO = _core.REPO
RECONCILE = _core.RECONCILE

MUTATIONS = [
    # ── Observer verification and integrity, on this path ──────────────
    {
        "id": "O-01",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "an observer integrity failure is SensorIntegrityFailure at Proven, not an inability to prove",
        "old": "    let mut draft = Draft::new(ctx);\n    let obs = match verify_observer(observer, ctx, &mut draft) {\n        ObserverCheck::Ok(o) => o,\n        ObserverCheck::IntegrityFailure(reason) => {\n            return draft.finish(\n                ReconciliationResult::SensorIntegrityFailure,\n                EvidenceStrength::Proven,\n                reason,\n            )\n        }",
        "new": "    let mut draft = Draft::new(ctx);\n    let obs = match verify_observer(observer, ctx, &mut draft) {\n        ObserverCheck::Ok(o) => o,\n        ObserverCheck::IntegrityFailure(reason) => return draft.cannot_prove(reason),",
    },
    {
        "id": "O-02",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "a replayed batch is recorded as replay on the observation path too",
        "old": "    draft.replay_detected = obs.replay_detected;\n\n    // Locate the target.",
        "new": "    draft.replay_detected = false;\n\n    // Locate the target.",
    },
    # ── Target location: a target names exactly one record ─────────────
    {
        "id": "O-03",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "an Observation target names one batch; a sequence not present is TargetNotFound, not the nearest batch",
        "old": "            let Some(b) = obs.batches.iter().find(|b| b.sequence == batch_sequence.0) else {\n                return draft.cannot_prove(ReasonCode::TargetNotFound);\n            };\n            let Some(o) = b.batch.observations.get(index as usize) else {",
        "new": "            let Some(b) = obs\n                .batches\n                .iter()\n                .find(|b| b.sequence == batch_sequence.0)\n                .or(obs.batches.first())\n            else {\n                return draft.cannot_prove(ReasonCode::TargetNotFound);\n            };\n            let Some(o) = b.batch.observations.get(index as usize) else {",
    },
    {
        "id": "O-04",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "an Observation target names one observation; an index not present is TargetNotFound, not observation zero",
        "old": "            let Some(o) = b.batch.observations.get(index as usize) else {\n                return draft.cannot_prove(ReasonCode::TargetNotFound);\n            };",
        "new": "            let Some(o) = b\n                .batch\n                .observations\n                .get(index as usize)\n                .or(b.batch.observations.first())\n            else {\n                return draft.cannot_prove(ReasonCode::TargetNotFound);\n            };",
    },
    {
        "id": "O-05",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "a KernelEvent target names one event; an index not present is TargetNotFound, not event zero",
        "old": "            let Some(e) = b.batch.kernel_events.get(index as usize) else {\n                return draft.cannot_prove(ReasonCode::TargetNotFound);\n            };",
        "new": "            let Some(e) = b\n                .batch\n                .kernel_events\n                .get(index as usize)\n                .or(b.batch.kernel_events.first())\n            else {\n                return draft.cannot_prove(ReasonCode::TargetNotFound);\n            };",
    },
    {
        "id": "O-06",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "a kernel event the probe could not bind to an instance is unbound, and unboundness is not assumed away",
        "old": "                e.attribution.claimed_agent_id().map(str::to_string),\n                e.claimed_decision_id,\n                e.bound.is_some(),",
        "new": "                e.attribution.claimed_agent_id().map(str::to_string),\n                e.claimed_decision_id,\n                true,",
    },
    {
        "id": "O-07",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "the record cites the observation it is about",
        "old": "    draft.evidence.push(target_ref);\n    draft.decision_id = claimed_decision.map(DecisionId::from_bytes);",
        "new": "    let _ = target_ref;\n    draft.decision_id = claimed_decision.map(DecisionId::from_bytes);",
    },
    {
        "id": "O-08",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "the record carries the decision the observation claimed",
        "old": "    draft.decision_id = claimed_decision.map(DecisionId::from_bytes);\n    let window = CoverageWindow {\n        from_ms: batch.batch.claimed_from_ms,",
        "new": "    draft.decision_id = None;\n    let window = CoverageWindow {\n        from_ms: batch.batch.claimed_from_ms,",
    },
    {
        "id": "O-09",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "the window compared against the expected-side statement is the batch's own claimed window",
        "old": "    let window = CoverageWindow {\n        from_ms: batch.batch.claimed_from_ms,\n        to_ms: batch.batch.claimed_to_ms,\n    };",
        "new": "    let window = CoverageWindow {\n        from_ms: batch.batch.claimed_from_ms,\n        to_ms: batch.batch.claimed_from_ms,\n    };",
    },
    {
        "id": "O-10",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "availability over the window is computed from the health record, not asserted",
        "old": "    draft.availability =\n        observer\n            .health\n            .availability_for(&window, ctx.verification_time_ms, ctx.health_max_age_ms);\n    draft.temporal = TemporalComparison::WithinWindow;",
        "new": "    draft.availability = ObservationAvailability::Covered { window };\n    draft.temporal = TemporalComparison::WithinWindow;",
    },
    # ── Clock and observer state, on this path ─────────────────────────
    {
        "id": "O-11",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "a forward-set collector clock cannot saturate staleness to age zero (observation path)",
        "old": "        return draft.cannot_prove(ReasonCode::HealthNotYetEmitted);\n    }\n\n    if let Some(reason) = state_reason(obs.health.state) {",
        "new": "        let _ = ReasonCode::HealthNotYetEmitted;\n    }\n\n    if let Some(reason) = state_reason(obs.health.state) {",
    },
    {
        "id": "O-12",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "observer state gates the observation path at all",
        "old": "    if let Some(reason) = state_reason(obs.health.state) {\n        return match obs.health.state {",
        "new": "    if false {\n        let reason = ReasonCode::ObserverDegraded;\n        return match obs.health.state {",
    },
    {
        "id": "O-13",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "a quarantined observer yields SensorIntegrityFailure on the observation path, never a mere inability to prove",
        "old": "            ObserverState::Quarantined => draft.finish(\n                ReconciliationResult::SensorIntegrityFailure,\n                EvidenceStrength::Attested,\n                reason,\n            ),",
        "new": "            ObserverState::Quarantined => draft.cannot_prove(reason),",
    },
    {
        "id": "O-14",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "a recovering or continuity-unverified observer yields ContinuityFailure on the observation path",
        "old": "            ObserverState::Recovering | ObserverState::ContinuityUnverified => draft.finish(\n                ReconciliationResult::ContinuityFailure,\n                EvidenceStrength::Attested,\n                reason,\n            ),",
        "new": "            ObserverState::Recovering | ObserverState::ContinuityUnverified => {\n                draft.cannot_prove(reason)\n            }",
    },
    {
        "id": "O-15",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "a degraded observer cannot support an attribution on the observation path",
        "old": "    if let Some(reason) = state_reason(obs.health.state) {\n        return match obs.health.state {\n            ObserverState::Quarantined => draft.finish(",
        "new": "    if let Some(reason) =\n        state_reason(obs.health.state).filter(|_| obs.health.state != ObserverState::Degraded)\n    {\n        return match obs.health.state {\n            ObserverState::Quarantined => draft.finish(",
    },
    {
        "id": "O-16",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "an observer whose integrity is unknown cannot support an attribution on the observation path",
        "old": "    if let Some(reason) = state_reason(obs.health.state) {\n        return match obs.health.state {\n            ObserverState::Quarantined => draft.finish(\n                ReconciliationResult::SensorIntegrityFailure,",
        "new": "    if let Some(reason) = state_reason(obs.health.state)\n        .filter(|_| obs.health.state != ObserverState::IntegrityUnknown)\n    {\n        return match obs.health.state {\n            ObserverState::Quarantined => draft.finish(\n                ReconciliationResult::SensorIntegrityFailure,",
    },
    {
        "id": "O-16b",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "an unbound reference establishes no instance, and unboundness is not assumed away",
        "old": "    if !has_instance {\n        draft.identity = IdentityComparison::UnboundReferencesOnly { references: 1 };",
        "new": "    if false {\n        draft.identity = IdentityComparison::UnboundReferencesOnly { references: 1 };",
    },
    # ── Attribution preconditions ──────────────────────────────────────
    {
        "id": "O-17",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "an observation with no claimed agent attributes to nobody",
        "old": "    let Some(agent) = claimed_agent else {\n        return draft.cannot_prove(ReasonCode::AttributionNotEstablished);\n    };",
        "new": "    let agent = claimed_agent.unwrap_or_default();",
    },
    {
        "id": "O-18",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "an Open-policy (unverified-provenance) mechanism label cannot support an attribution (observation path)",
        "old": "    if obs.health.probe_policy == ProbePolicy::Open {\n        return draft.cannot_prove(ReasonCode::ProvenanceUnverifiedOpenPolicy);\n    }",
        "new": "    if false {\n        return draft.cannot_prove(ReasonCode::ProvenanceUnverifiedOpenPolicy);\n    }",
    },
    # ── Expected-side completeness: the precondition for UnattributedEffect ─
    {
        "id": "O-19",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "an unknown expected side is CANNOT_PROVE and never an accusation",
        "old": "        ExpectedSideCoverage::Unknown => {\n            return draft.cannot_prove(ReasonCode::ExpectedSideCompletenessUnknown)\n        }",
        "new": "        ExpectedSideCoverage::Unknown => {\n            return draft.finish(\n                ReconciliationResult::UnattributedEffect,\n                EvidenceStrength::Attested,\n                ReasonCode::ExpectedSideCompletenessUnknown,\n            )\n        }",
    },
    {
        "id": "O-20",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "the expected-side statement must verify under the verifier's own decision-point anchors",
        "old": "    if stmt.verify(&ctx.decision_point_anchors).is_err() {\n        return draft.cannot_prove(ReasonCode::ExpectedSideStatementInvalid);\n    }",
        "new": "    if false {\n        return draft.cannot_prove(ReasonCode::ExpectedSideStatementInvalid);\n    }",
    },
    {
        "id": "O-21",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "the record cites the coverage statement its accusation rests on",
        "old": "    draft.evidence.push(EvidenceRef::CoverageStatement {\n        decision_point_id: DecisionPointId(stmt.decision_point_id.clone()),\n        issued_at_ms: stmt.issued_at_ms,\n    });",
        "new": "    let _ = &stmt.decision_point_id;",
    },
    {
        "id": "O-22",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "a statement about another agent does not settle this agent's expected side",
        "old": "    if stmt.agent_id != agent || !stmt.window.covers(&window) {",
        "new": "    if !stmt.window.covers(&window) {",
    },
    {
        "id": "O-23",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "a statement whose window does not cover the observation's window does not settle it",
        "old": "    if stmt.agent_id != agent || !stmt.window.covers(&window) {\n        return draft.cannot_prove(ReasonCode::ExpectedSideStatementDoesNotCover);\n    }",
        "new": "    if stmt.agent_id != agent {\n        return draft.cannot_prove(ReasonCode::ExpectedSideStatementDoesNotCover);\n    }",
    },
    {
        "id": "O-24",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "an observation whose decision IS in the attested set is not unattributed",
        "old": "        Some(d) if stmt.decision_ids.contains(&d) => {",
        "new": "        Some(d) if !stmt.decision_ids.contains(&d) => {",
    },
    {
        "id": "O-25",
        "pkg": "aip-reconcile",
        "file": RECONCILE,
        "invariant": "UnattributedEffect is Attested, and its strength is not raised",
        "old": "        _ => draft.finish(\n            ReconciliationResult::UnattributedEffect,\n            EvidenceStrength::Attested,\n            ReasonCode::NoExpectationAttested,\n        ),",
        "new": "        _ => draft.finish(\n            ReconciliationResult::UnattributedEffect,\n            EvidenceStrength::Proven,\n            ReasonCode::NoExpectationAttested,\n        ),",
    },
]

if __name__ == "__main__":
    sys.exit(
        _core.run_matrix(
            MUTATIONS,
            REPO / "validation/mutation/OBSERVATION_MUTATION_RESULTS.json",
            sys.argv[1:] or None,
            ["aip-reconcile"],
        )
    )
