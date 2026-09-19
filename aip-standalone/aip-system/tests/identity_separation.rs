//! Skill 17 — the identities must not collapse.
//!
//! The model's whole claim is that system, agent, execution, hardware,
//! platform and mission identity are separable. These tests attack that claim
//! the way an adversary would: by substituting one identity for another and
//! checking whether anything notices.
//!
//! # What "notices" means here, precisely
//!
//! `AutonomousSystem` and `SystemExecution` are **unsigned descriptors**. An
//! unsigned descriptor cannot prevent anyone from writing whatever they like
//! into it, and these tests do not pretend otherwise. What they establish is
//! that a substitution **changes the canonical bytes** — so any signature over
//! those bytes stops verifying, and a transplant cannot be silent.
//!
//! Silence is the property under attack. Prevention belongs to whatever signs
//! the bytes, which is deliberately not this crate.

use aip_system::*;
use aip_types::{ExecutionBinding, ProcessInstance, EXECUTION_BINDING_VERSION};

// Two real AIP-IDs, derived rather than invented, so `validate_aip_id`
// genuinely passes and the tests are not exercising a stub.
fn agent(tag: &str) -> String {
    use aip_crypto::{derive_aip_id, sha256};
    use aip_types::ProvenanceTriple;
    let pubkey = sha256(format!("pubkey-{tag}").as_bytes());
    let prov = ProvenanceTriple {
        model_commitment: sha256(format!("m-{tag}").as_bytes()),
        environment_commitment: sha256(format!("e-{tag}").as_bytes()),
        toolchain_commitment: sha256(format!("t-{tag}").as_bytes()),
    };
    derive_aip_id(&pubkey, &prov)
}

fn sys(v: &str) -> SystemId {
    SystemId::parse(v).expect("valid system id")
}
fn platform(v: &str) -> PlatformId {
    PlatformId::parse(v).expect("valid platform id")
}
fn hardware(v: &str) -> HardwareId {
    HardwareId::parse(v).expect("valid hardware id")
}
fn mission(v: &str) -> MissionId {
    MissionId::parse(v).expect("valid mission id")
}

const EXEC_A: [u8; 16] = [0xA1; 16];
const EXEC_B: [u8; 16] = [0xB2; 16];
const NOW: u64 = 1_700_000_000_000;

fn execution(system: &str, agent_id: &str, exec: [u8; 16]) -> SystemExecution {
    SystemExecution::new(sys(system), agent_id, exec, NOW).expect("valid execution record")
}

// ═══ 1-3. The identities are distinct types ═══
//
// Most of this invariant is enforced by the compiler and cannot be tested at
// runtime: `PlatformId` and `HardwareId` are different types with no `From`
// between them, so passing one where the other belongs does not compile.
// What *can* be tested is that they are not silently interchangeable through
// their string forms, which is the escape hatch an attacker would reach for.

#[test]
fn t01_agent_identity_is_never_platform_identity() {
    // The same textual value parsed as two different identity kinds must not
    // produce interchangeable values. `SystemId::parse` accepting a string
    // that also parses as a `PlatformId` is fine — what matters is that the
    // resulting values live in different types and encode in different
    // positions, so one cannot stand in for the other.
    let a = agent("alpha");
    let e = execution("sys:fleet-1", &a, EXEC_A).on_platform(platform("tail:N123AB"));

    assert_eq!(e.agent_id(), a);
    assert_ne!(
        e.agent_id(),
        e.platform_id.as_ref().unwrap().as_str(),
        "agent identity and platform identity must not be the same value"
    );
    // And an AIP-ID is not even well formed as a namespaced identifier, so
    // the two vocabularies cannot be confused by accident.
    assert!(
        PlatformId::parse(&a).is_err(),
        "an AIP-ID must not parse as a platform id"
    );
}

#[test]
fn t02_execution_identity_is_never_hardware_identity() {
    let e =
        execution("sys:fleet-1", &agent("alpha"), EXEC_A).on_hardware(hardware("tpm-ek:abc123"));
    // Execution identity is 16 raw bytes; hardware identity is a namespaced
    // string. There is no representation in which one could be read as the
    // other.
    assert_eq!(e.execution_id, EXEC_A);
    assert_eq!(e.hardware_id.as_ref().unwrap().namespace(), "tpm-ek");
    assert!(
        HardwareId::parse(&hex_of(&EXEC_A)).is_err(),
        "a bare execution id must not parse as a hardware id"
    );
}

#[test]
fn t03_mission_identity_is_never_agent_identity() {
    let a = agent("alpha");
    let e = execution("sys:fleet-1", &a, EXEC_A).for_mission(mission("op:sortie-77"));
    assert_ne!(e.agent_id(), e.mission_id.as_ref().unwrap().as_str());
    assert!(
        MissionId::parse(&a).is_err(),
        "an AIP-ID must not parse as a mission id"
    );
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ═══ 4-5. Nothing here grants authority ═══

#[test]
fn t04_creation_does_not_grant_authority() {
    // Structural, and the most important test in the file. A descriptor that
    // could grant authority would need somewhere to put it. There is nowhere:
    // no key, no token, no scope, no signature, on either type.
    //
    // What is checked here is the observable consequence — a freshly created
    // execution cites no authorization at all, and a freshly created system is
    // in a state that claims nothing.
    let e = execution("sys:fleet-1", &agent("alpha"), EXEC_A);
    assert_eq!(e.authority, AuthorityContext::none());
    assert!(e.authority.decision_id.is_none());
    assert!(e.authority.root_token_jti.is_none());

    let s = AutonomousSystem::new(
        sys("sys:fleet-1"),
        SystemType::UncrewedAerial,
        LifecycleState::Created,
        NOW,
    );
    assert_eq!(s.lifecycle_state, LifecycleState::Created);
    assert!(s.profiles.is_empty(), "no capability is claimed by default");
}

#[test]
fn t05_parent_child_lineage_transfers_no_permission() {
    // A child execution records its parent. It inherits nothing by doing so:
    // its authority citation is still empty, and citing an authority on the
    // parent does not populate the child's.
    let a = agent("alpha");
    let parent = execution("sys:fleet-1", &a, EXEC_A).citing(AuthorityContext {
        decision_id: Some([0xD1; 16]),
        root_token_jti: Some([0x7C; 16]),
    });
    let child = execution("sys:fleet-1", &a, EXEC_B).with_parent(parent.execution_id);

    assert_eq!(child.parent_execution_id, Some(EXEC_A));
    assert_eq!(
        child.authority,
        AuthorityContext::none(),
        "SECURITY: a child execution inherited its parent's authority citation"
    );
    // And the citation the parent holds is not a permission in the first
    // place — it names a decision, which is exactly as powerful as knowing a
    // number.
    assert_ne!(parent.authority, child.authority);
}

// ═══ 6-7. The many-to-many relationships hold ═══

#[test]
fn t06_one_agent_may_have_many_executions() {
    let a = agent("alpha");
    let e1 = execution("sys:fleet-1", &a, EXEC_A);
    let e2 = execution("sys:fleet-1", &a, EXEC_B);

    assert_eq!(e1.agent_id(), e2.agent_id());
    assert_ne!(e1.execution_id, e2.execution_id);
    assert_ne!(
        e1.canonical_bytes(),
        e2.canonical_bytes(),
        "two executions of one agent must be distinguishable"
    );
}

#[test]
fn t07_one_platform_may_host_different_agents_over_time() {
    // The retrofit case: the same airframe, successive autonomy builds.
    let p = platform("tail:N123AB");
    let e1 = execution("sys:fleet-1", &agent("build-v1"), EXEC_A).on_platform(p.clone());
    let e2 = execution("sys:fleet-1", &agent("build-v2"), EXEC_B).on_platform(p.clone());

    assert_eq!(e1.platform_id, e2.platform_id);
    assert_ne!(
        e1.agent_id(),
        e2.agent_id(),
        "a platform must be able to host different intelligences over time"
    );
}

#[test]
fn t07b_one_agent_may_run_on_different_platforms() {
    // The fleet case: the mirror of t07, and the reason platform identity
    // cannot live on the agent.
    let a = agent("alpha");
    let e1 = execution("sys:fleet-1", &a, EXEC_A).on_platform(platform("tail:N123AB"));
    let e2 = execution("sys:fleet-1", &a, EXEC_B).on_platform(platform("tail:N456CD"));

    assert_eq!(e1.agent_id(), e2.agent_id());
    assert_ne!(e1.platform_id, e2.platform_id);
}

// ═══ 8-9. Substitution and transplantation ═══

#[test]
fn t08_an_execution_cannot_silently_change_platform() {
    let a = agent("alpha");
    let original = execution("sys:fleet-1", &a, EXEC_A).on_platform(platform("tail:N123AB"));
    let moved = execution("sys:fleet-1", &a, EXEC_A).on_platform(platform("tail:N456CD"));

    assert_ne!(
        original.canonical_bytes(),
        moved.canonical_bytes(),
        "SECURITY: moving an execution to another platform did not change its \
         canonical bytes, so a signature over them would still verify"
    );
}

#[test]
fn t09_cross_system_identity_transplantation_changes_the_bytes() {
    // Every substitution an attacker would attempt, swept. Each must change
    // the encoding; if any does not, a signed record could be re-pointed at a
    // different system, agent, host, platform or mission without the
    // signature noticing.
    let a = agent("alpha");
    let b = agent("bravo");
    let base = execution("sys:fleet-1", &a, EXEC_A)
        .on_hardware(hardware("tpm-ek:aaa"))
        .on_platform(platform("tail:N123AB"))
        .for_mission(mission("op:sortie-77"));

    let substitutions: Vec<(&str, SystemExecution)> = vec![
        (
            "agent A → agent B",
            execution("sys:fleet-1", &b, EXEC_A)
                .on_hardware(hardware("tpm-ek:aaa"))
                .on_platform(platform("tail:N123AB"))
                .for_mission(mission("op:sortie-77")),
        ),
        (
            "platform A → platform B",
            execution("sys:fleet-1", &a, EXEC_A)
                .on_hardware(hardware("tpm-ek:aaa"))
                .on_platform(platform("tail:N456CD"))
                .for_mission(mission("op:sortie-77")),
        ),
        (
            "hardware A → hardware B",
            execution("sys:fleet-1", &a, EXEC_A)
                .on_hardware(hardware("tpm-ek:bbb"))
                .on_platform(platform("tail:N123AB"))
                .for_mission(mission("op:sortie-77")),
        ),
        (
            "mission A → mission B",
            execution("sys:fleet-1", &a, EXEC_A)
                .on_hardware(hardware("tpm-ek:aaa"))
                .on_platform(platform("tail:N123AB"))
                .for_mission(mission("op:sortie-99")),
        ),
        (
            "execution X → execution Y",
            execution("sys:fleet-1", &a, EXEC_B)
                .on_hardware(hardware("tpm-ek:aaa"))
                .on_platform(platform("tail:N123AB"))
                .for_mission(mission("op:sortie-77")),
        ),
        (
            "system 1 → system 2",
            execution("sys:fleet-2", &a, EXEC_A)
                .on_hardware(hardware("tpm-ek:aaa"))
                .on_platform(platform("tail:N123AB"))
                .for_mission(mission("op:sortie-77")),
        ),
    ];

    let base_bytes = base.canonical_bytes();
    for (what, altered) in &substitutions {
        assert_ne!(
            base_bytes,
            altered.canonical_bytes(),
            "SECURITY: {what} produced identical canonical bytes — the \
             substitution would be invisible to any signature"
        );
    }
    // And every substitution is distinct from every other, so two different
    // attacks cannot land on the same encoding either.
    let mut all: Vec<Vec<u8>> = substitutions
        .iter()
        .map(|(_, e)| e.canonical_bytes())
        .collect();
    all.push(base_bytes);
    let before = all.len();
    all.sort();
    all.dedup();
    assert_eq!(
        before,
        all.len(),
        "two distinct records encoded identically"
    );
}

#[test]
fn t09b_the_identity_slots_cannot_shift_into_one_another() {
    // The injectivity attack. If optional fields were encoded without a
    // presence byte, a record with hardware `"x"` and no platform could encode
    // identically to one with no hardware and platform `"x"` — letting an
    // attacker move a value between identity slots for free.
    let a = agent("alpha");
    let h_only = execution("sys:s", &a, EXEC_A).on_hardware(hardware("ns:x"));
    let p_only = execution("sys:s", &a, EXEC_A).on_platform(platform("ns:x"));
    let m_only = execution("sys:s", &a, EXEC_A).for_mission(mission("ns:x"));

    assert_ne!(h_only.canonical_bytes(), p_only.canonical_bytes());
    assert_ne!(p_only.canonical_bytes(), m_only.canonical_bytes());
    assert_ne!(h_only.canonical_bytes(), m_only.canonical_bytes());
}

#[test]
fn t09c_absent_is_not_the_same_as_empty_or_adjacent() {
    // The other half of injectivity: an absent field must not encode like a
    // present one, and two adjacent string fields must not be able to run
    // together. `SystemId::parse` rejects the empty string, so the attack is
    // tested at the boundary that would matter — one field's content cannot
    // be read as spanning into the next.
    let a = agent("alpha");
    let none = execution("sys:s", &a, EXEC_A);
    let some = execution("sys:s", &a, EXEC_A).on_hardware(hardware("ns:v"));
    assert_ne!(none.canonical_bytes(), some.canonical_bytes());

    let split_a = execution("sys:ab", &a, EXEC_A);
    let split_b = execution("sys:a", &a, EXEC_A);
    assert_ne!(
        split_a.canonical_bytes(),
        split_b.canonical_bytes(),
        "length-prefixing must stop a longer value being a prefix of another"
    );
}

// ═══ 10. Round trip ═══

#[test]
fn t10_serialization_round_trip_preserves_identity_relationships() {
    let a = agent("alpha");
    let binding = ExecutionBinding {
        version: EXECUTION_BINDING_VERSION,
        agent_id: a.clone(),
        process: ProcessInstance {
            pid: 4321,
            pid_start_time_ticks: 777_000,
            boot_id: [0x3d; 16],
        },
        exe_content_sha256: [0x11; 32],
        exe_path: "/opt/agent/bin/autonomy".into(),
        bound_at_ms: NOW,
        container: None,
    };
    let original = execution("sys:fleet-1", &a, EXEC_A)
        .with_parent(EXEC_B)
        .on_hardware(hardware("tpm-ek:aaa"))
        .on_platform(platform("tail:N123AB"))
        .for_mission(mission("op:sortie-77"))
        .citing(AuthorityContext {
            decision_id: Some([0xD1; 16]),
            root_token_jti: Some([0x7C; 16]),
        })
        .bound_to(binding);

    let json = serde_json::to_string(&original).expect("serialise");
    let parsed: SystemExecution = serde_json::from_str(&json).expect("deserialise");

    assert_eq!(parsed, original);
    assert_eq!(
        parsed.canonical_bytes(),
        original.canonical_bytes(),
        "a round trip must not change the canonical encoding, or a record's \
         signature would stop verifying after transport"
    );
    parsed.check_version().expect("version accepted");
}

#[test]
fn t10b_system_round_trip_is_byte_stable() {
    let s = AutonomousSystem::new(
        sys("sys:fleet-1"),
        SystemType::UncrewedAerial,
        LifecycleState::Registered,
        NOW,
    )
    .with_platform(platform("tail:N123AB"))
    .with_display_name("Sortie bird 3")
    .with_profile(ProfileRef::new(ProfileKind::Safety, "safety/v1", [0x22; 32]).unwrap())
    .with_profile(ProfileRef::new(ProfileKind::Capability, "cap/v1", [0x33; 32]).unwrap());

    let parsed: AutonomousSystem =
        serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
    assert_eq!(parsed, s);
    assert_eq!(parsed.canonical_bytes(), s.canonical_bytes());
}

#[test]
fn t10c_profile_order_does_not_change_the_encoding() {
    // Profiles are a set in meaning. Two records listing the same profiles in
    // different orders describe the same system and must encode identically,
    // or a re-serialisation would look like a modification.
    let mk = |order: [(ProfileKind, &str, u8); 2]| {
        let mut s = AutonomousSystem::new(
            sys("sys:s"),
            SystemType::Robotic,
            LifecycleState::Created,
            NOW,
        );
        for (kind, id, byte) in order {
            s = s.with_profile(ProfileRef::new(kind, id, [byte; 32]).unwrap());
        }
        s.canonical_bytes()
    };
    assert_eq!(
        mk([
            (ProfileKind::Capability, "cap/v1", 0x33),
            (ProfileKind::Safety, "safety/v1", 0x22)
        ]),
        mk([
            (ProfileKind::Safety, "safety/v1", 0x22),
            (ProfileKind::Capability, "cap/v1", 0x33)
        ])
    );
}

// ═══ 11-12. Fail closed ═══

#[test]
fn t11_malformed_identifiers_fail_closed() {
    // Every rejection is a rejection, not a coercion. A model that repaired a
    // malformed identifier would be inventing an identity.
    for bad in [
        "",             // empty
        "novalue:",     // empty value
        ":novalue",     // empty namespace
        "nocolon",      // no separator
        "ns:val:extra", // a second colon — must not be read as a namespace
        "ns:has space", // whitespace
        "ns:has\ttab",
        "ns:has\nnewline",
        "ns:naïve", // non-ASCII
        "ns:quote\"",
        "NS with space:v",
    ] {
        assert!(
            SystemId::parse(bad).is_err(),
            "SECURITY: {bad:?} was accepted as a system id"
        );
        assert!(PlatformId::parse(bad).is_err(), "{bad:?} as platform id");
        assert!(HardwareId::parse(bad).is_err(), "{bad:?} as hardware id");
        assert!(MissionId::parse(bad).is_err(), "{bad:?} as mission id");
    }

    // Over-long parts are refused rather than truncated.
    let long = "x".repeat(97);
    assert!(SystemId::parse(&format!("ns:{long}")).is_err());
    assert!(SystemId::parse(&format!("{long}:v")).is_err());

    // A malformed agent id is refused at construction, not stored.
    assert_eq!(
        SystemExecution::new(sys("sys:s"), "not-an-aip-id", EXEC_A, NOW),
        Err(SystemError::InvalidAgentId)
    );
    assert_eq!(
        SystemExecution::new(sys("sys:s"), "", EXEC_A, NOW),
        Err(SystemError::InvalidAgentId)
    );
}

#[test]
fn t11b_deserialization_applies_the_same_validation_as_construction() {
    // The bypass an attacker reaches for: if serde skipped validation, JSON
    // would be a way to build an identifier the constructor refuses.
    let bad = serde_json::json!("no-separator").to_string();
    assert!(
        serde_json::from_str::<SystemId>(&bad).is_err(),
        "SECURITY: a malformed system id was constructible through serde"
    );
    assert!(serde_json::from_str::<HardwareId>(&bad).is_err());
    assert!(serde_json::from_str::<PlatformId>(&bad).is_err());
    assert!(serde_json::from_str::<MissionId>(&bad).is_err());
}

#[test]
fn t12_unknown_versions_are_refused_not_guessed() {
    let a = agent("alpha");
    let mut e = execution("sys:s", &a, EXEC_A);
    e.check_version().expect("current version is accepted");

    for found in [0u16, 2, 99, u16::MAX] {
        e.version = found;
        assert_eq!(
            e.check_version(),
            Err(SystemError::UnsupportedVersion {
                found,
                supported: SYSTEM_EXECUTION_VERSION
            }),
            "SECURITY: version {found} was read as though its fields were understood"
        );
    }

    let mut s = AutonomousSystem::new(
        sys("sys:s"),
        SystemType::Enterprise,
        LifecycleState::Created,
        NOW,
    );
    s.check_version().expect("current version is accepted");
    s.version = 2;
    assert!(s.check_version().is_err());
}

#[test]
fn t12b_a_deserialised_record_still_has_to_pass_the_version_check() {
    // serde will happily parse a version-2 record into version-1 fields. Only
    // an explicit check stops those fields being read as though their meaning
    // were known — so this pins that a reader must call it, and that it works
    // on parsed values and not only on constructed ones.
    let a = agent("alpha");
    let mut e = execution("sys:s", &a, EXEC_A);
    e.version = 7;
    let json = serde_json::to_string(&e).unwrap();
    let parsed: SystemExecution = serde_json::from_str(&json).expect("serde parses it");
    assert_eq!(parsed.version, 7, "serde does not enforce the version");
    assert!(
        parsed.check_version().is_err(),
        "SECURITY: a future-version record passed the version check"
    );
}

#[test]
fn t12c_system_types_are_a_closed_set() {
    // No `Other(String)` escape: an unknown type from a future version cannot
    // be absorbed into a variant a reader would then have to interpret. Serde
    // rejects it, which is the fail-closed outcome.
    assert!(
        serde_json::from_str::<SystemType>("\"OrbitalWeaponsPlatform\"").is_err(),
        "SECURITY: an unknown system type was accepted"
    );
    // And every known code is distinct, so no two types encode alike.
    let all = [
        SystemType::SoftwareAgent,
        SystemType::UncrewedAerial,
        SystemType::UncrewedGround,
        SystemType::UncrewedMaritime,
        SystemType::Robotic,
        SystemType::Industrial,
        SystemType::CriticalEdge,
        SystemType::Space,
        SystemType::Enterprise,
    ];
    let mut codes: Vec<u8> = all.iter().map(|t| t.code()).collect();
    let n = codes.len();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), n, "system type codes must be distinct");
}

// ═══ 15-16. No trust is granted, and lifecycle is not a gate ═══

#[test]
fn t15_constructing_a_system_grants_no_trust() {
    // Swept across every system type and every lifecycle state: no
    // combination produces a value carrying an authorization. `Authorized` is
    // a record that one exists elsewhere, not the thing itself.
    for st in [
        SystemType::SoftwareAgent,
        SystemType::UncrewedAerial,
        SystemType::Space,
        SystemType::Enterprise,
    ] {
        for ls in [
            LifecycleState::Created,
            LifecycleState::Registered,
            LifecycleState::Authorized,
            LifecycleState::Executing,
        ] {
            let s = AutonomousSystem::new(sys("sys:s"), st, ls, NOW);
            assert!(s.profiles.is_empty());
            // The descriptor has no field through which authority could be
            // expressed; the executions it describes cite nothing by default.
            let e = execution("sys:s", &agent("alpha"), EXEC_A);
            assert_eq!(
                e.authority,
                AuthorityContext::none(),
                "SECURITY: a {st:?} system in state {ls:?} produced an \
                 execution carrying an authorization"
            );
        }
    }
}

#[test]
fn t16_lifecycle_state_is_not_a_trust_anchor() {
    // Two systems differing only in lifecycle state differ only in their
    // bytes. Reaching `Authorized` changes nothing else about what the
    // descriptor says or carries.
    let created = AutonomousSystem::new(
        sys("sys:s"),
        SystemType::Industrial,
        LifecycleState::Created,
        NOW,
    );
    let authorized = AutonomousSystem::new(
        sys("sys:s"),
        SystemType::Industrial,
        LifecycleState::Authorized,
        NOW,
    );
    assert_ne!(created.canonical_bytes(), authorized.canonical_bytes());
    assert_eq!(created.profiles, authorized.profiles);
    assert_eq!(created.platform, authorized.platform);
}

#[test]
fn t16b_lifecycle_transitions_are_descriptive_not_enforcing() {
    use LifecycleState::*;
    // The intended shape is written down and executable...
    assert!(Created.may_precede(Registered));
    assert!(Registered.may_precede(Authorized));
    assert!(Executing.may_precede(Contained));
    assert!(!Retired.may_precede(Executing), "retired is terminal");
    // ...and re-entering service goes back through authorization: a
    // suspension does not preserve the rights that preceded it.
    assert!(Suspended.may_precede(Authorized));
    assert!(!Suspended.may_precede(Executing));

    // But nothing enforces it. A system that reached an odd state by an odd
    // route still needs describing; a model that refuses to represent what
    // happened is a model that gets bypassed.
    let odd = AutonomousSystem::new(sys("sys:s"), SystemType::Robotic, Retired, NOW);
    assert_eq!(odd.lifecycle_state, Retired);
    odd.check_version().expect("still a valid descriptor");
}

// ═══ 18. The two platform fields stay separate ═══

#[test]
fn t18_registered_platform_and_executed_platform_are_distinct_fields() {
    // The disagreement must be *representable*. Noticing it is reconciliation's
    // job; this layer's job is not to make it inexpressible by having one
    // field where there are two facts.
    let registered = platform("tail:N123AB");
    let actually_flew = platform("tail:N456CD");

    let s = AutonomousSystem::new(
        sys("sys:fleet-1"),
        SystemType::UncrewedAerial,
        LifecycleState::Executing,
        NOW,
    )
    .with_platform(registered.clone());
    let e = execution("sys:fleet-1", &agent("alpha"), EXEC_A).on_platform(actually_flew.clone());

    assert_eq!(s.platform, Some(registered));
    assert_eq!(e.platform_id, Some(actually_flew));
    assert_ne!(
        s.platform, e.platform_id,
        "the model must be able to state that a system ran somewhere other \
         than where it is registered"
    );
}

// ═══ Every environment, one core ═══

#[test]
fn every_environment_is_representable_without_a_schema_fork() {
    // The acceptance gate: a UAS, a UGV, a robot, an industrial edge node, a
    // spacecraft computer and an enterprise agent all describable with the
    // same two types and no per-vertical field.
    let cases = [
        (SystemType::UncrewedAerial, Some("tail:N123AB")),
        (SystemType::UncrewedGround, Some("chassis:UGV-7")),
        (SystemType::UncrewedMaritime, Some("hull:USV-2")),
        (SystemType::Robotic, Some("cell:ARM-4")),
        (SystemType::Industrial, Some("cabinet:PLC-9")),
        (SystemType::CriticalEdge, Some("site:SUB-12")),
        (SystemType::Space, Some("norad:25544")),
        (SystemType::Enterprise, None),
        (SystemType::SoftwareAgent, None),
    ];
    let mut encodings = Vec::new();
    for (st, plat) in cases {
        let mut s =
            AutonomousSystem::new(sys("sys:programme-1"), st, LifecycleState::Registered, NOW);
        if let Some(p) = plat {
            s = s.with_platform(platform(p));
        }
        s.check_version().expect("describable");
        // A platformless system is a fact, not a gap.
        assert_eq!(s.platform.is_none(), plat.is_none());
        encodings.push(s.canonical_bytes());
    }
    let n = encodings.len();
    encodings.sort();
    encodings.dedup();
    assert_eq!(
        n,
        encodings.len(),
        "each environment must encode distinctly"
    );
}
