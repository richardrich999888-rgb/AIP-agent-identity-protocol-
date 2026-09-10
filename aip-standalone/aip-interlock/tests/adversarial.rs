//! The interlock under attack and under misconfiguration.
//!
//! Every test names the failure it is pinning. The pass condition is always
//! the same shape: the actuator is *not* permitted unless the host has just
//! proved, with a fresh counter under an anchored key, that it may be.

use aip_crypto::generate_ed25519_keypair;
use aip_interlock::*;
use aip_observe::ObserverState;
use aip_types::KeyPair;

const PERIOD_MS: u32 = 100;
const TOLERATED_MISSES: u8 = 2;
const EPOCH: [u8; 16] = [0xA5; 16];

fn profile(budget_ms: u64) -> ActuatorProfile {
    ActuatorProfile {
        actuator_id: "arm-joint-3".into(),
        safe_state: SafeState::DeEnergise,
        declared_by: "hazard-analysis-2026-09-10".into(),
        stopping_budget: StoppingBudget {
            max_trip_ms: budget_ms,
        },
    }
}

fn config() -> WatchdogConfig {
    WatchdogConfig {
        period_ms: PERIOD_MS,
        tolerated_misses: TOLERATED_MISSES,
    }
}

fn nominal() -> HostSignal {
    HostSignal {
        observer: ObserverState::Active,
        enforcement_degraded: false,
        operator_hold: false,
    }
}

struct Bench {
    host: KeyPair,
    anchors: InterlockAnchors,
    sender: HeartbeatSender<SoftwareCounter>,
    dog: Watchdog,
}

impl Bench {
    fn armed() -> Self {
        let host = generate_ed25519_keypair();
        let anchors = InterlockAnchors::new().trust("host:cc-1", &host.public_key);
        let mut sender = HeartbeatSender::new(
            "interlock:bench-1",
            "host:cc-1",
            EPOCH,
            SoftwareCounter::starting_at(1),
            &host.private_key,
        );
        let mut dog = Watchdog::new(config(), profile(1_000));
        let first = sender.next(nominal(), 0).unwrap();
        let first = verify_heartbeat(&first, &anchors).unwrap();
        dog.arm(&first, 0).unwrap();
        assert!(dog.actuator_permitted());
        Self {
            host,
            anchors,
            sender,
            dog,
        }
    }

    fn beat(&mut self, signal: HostSignal, now_ms: u64) -> HeartbeatOutcome {
        let hb = self.sender.next(signal, now_ms).unwrap();
        let hb = verify_heartbeat(&hb, &self.anchors).unwrap();
        self.dog.on_heartbeat(&hb, now_ms)
    }
}

#[test]
fn t01_silence_past_the_miss_budget_trips() {
    let mut b = Bench::armed();
    // Inside the budget: two full periods missed, still permitted.
    let within = u64::from(PERIOD_MS) * u64::from(TOLERATED_MISSES);
    assert_eq!(b.dog.on_tick(within), HeartbeatOutcome::Accepted);
    assert!(b.dog.actuator_permitted());
    // One more period and the interlock trips.
    let past = within + u64::from(PERIOD_MS);
    assert!(matches!(
        b.dog.on_tick(past),
        HeartbeatOutcome::Tripped(TripReason::Silence { periods_missed: 3 })
    ));
    assert!(!b.dog.actuator_permitted());
}

#[test]
fn t02_a_replayed_heartbeat_trips_immediately() {
    let mut b = Bench::armed();
    let hb = b.sender.next(nominal(), 100).unwrap();
    let verified = verify_heartbeat(&hb, &b.anchors).unwrap();
    assert_eq!(
        b.dog.on_heartbeat(&verified, 100),
        HeartbeatOutcome::Accepted
    );
    // Same bytes, same signature, a moment later: a capture replayed.
    assert!(matches!(
        b.dog.on_heartbeat(&verified, 150),
        HeartbeatOutcome::Tripped(TripReason::CounterNotIncreasing { last: 2, got: 2 })
    ));
    assert!(!b.dog.actuator_permitted());
}

#[test]
fn t03_a_counter_regression_trips() {
    let mut b = Bench::armed();
    // A second sender that restarted from 1 — a host that lost its counter.
    let mut restarted = HeartbeatSender::new(
        "interlock:bench-1",
        "host:cc-1",
        EPOCH,
        SoftwareCounter::starting_at(1),
        &b.host.private_key,
    );
    assert_eq!(b.beat(nominal(), 100), HeartbeatOutcome::Accepted); // counter 2
    let stale = restarted.next(nominal(), 200).unwrap(); // counter 1
    let stale = verify_heartbeat(&stale, &b.anchors).unwrap();
    assert!(matches!(
        b.dog.on_heartbeat(&stale, 200),
        HeartbeatOutcome::Tripped(TripReason::CounterNotIncreasing { last: 2, got: 1 })
    ));
}

#[test]
fn t04_a_heartbeat_for_another_epoch_trips() {
    let mut b = Bench::armed();
    let mut other_epoch = HeartbeatSender::new(
        "interlock:bench-1",
        "host:cc-1",
        [0x5A; 16],
        SoftwareCounter::starting_at(50),
        &b.host.private_key,
    );
    let hb = other_epoch.next(nominal(), 100).unwrap();
    let hb = verify_heartbeat(&hb, &b.anchors).unwrap();
    assert_eq!(
        b.dog.on_heartbeat(&hb, 100),
        HeartbeatOutcome::Tripped(TripReason::EpochMismatch)
    );
}

#[test]
fn t05_a_signed_withheld_condition_trips_even_though_it_verifies() {
    let mut b = Bench::armed();
    let hold = HostSignal {
        operator_hold: true,
        ..nominal()
    };
    let hb = b.sender.next(hold, 100).unwrap();
    // The heartbeat is genuine: it verifies.
    let verified = verify_heartbeat(&hb, &b.anchors).expect("a withheld heartbeat still verifies");
    assert_eq!(
        b.dog.on_heartbeat(&verified, 100),
        HeartbeatOutcome::Tripped(TripReason::Withheld(WithholdReason::OperatorHold))
    );
}

#[test]
fn t06_a_tampered_heartbeat_does_not_verify_and_counts_as_silence() {
    let mut b = Bench::armed();
    let mut hb = b.sender.next(nominal(), 100).unwrap();
    hb.heartbeat.counter += 10;
    assert_eq!(
        verify_heartbeat(&hb, &b.anchors),
        Err(HeartbeatError::PayloadHashMismatch)
    );
    // Nothing reached the watchdog, so time keeps running against the budget.
    let past = u64::from(PERIOD_MS) * (u64::from(TOLERATED_MISSES) + 1);
    assert!(matches!(b.dog.on_tick(past), HeartbeatOutcome::Tripped(_)));
}

#[test]
fn t07_arm_refuses_when_trip_time_exceeds_the_stopping_budget() {
    let host = generate_ed25519_keypair();
    let anchors = InterlockAnchors::new().trust("host:cc-1", &host.public_key);
    let mut sender = HeartbeatSender::new(
        "interlock:bench-1",
        "host:cc-1",
        EPOCH,
        SoftwareCounter::starting_at(1),
        &host.private_key,
    );
    // worst case = 100 × 3 = 300 ms; the hazard analysis allows 250.
    let mut dog = Watchdog::new(config(), profile(250));
    let first = sender.next(nominal(), 0).unwrap();
    let first = verify_heartbeat(&first, &anchors).unwrap();
    assert_eq!(
        dog.arm(&first, 0),
        Err(ArmError::TripTimeExceedsStoppingBudget {
            worst_case_ms: 300,
            budget_ms: 250
        })
    );
    assert!(!dog.actuator_permitted());
}

#[test]
fn t08_arm_refuses_a_first_heartbeat_that_is_not_nominal() {
    let host = generate_ed25519_keypair();
    let anchors = InterlockAnchors::new().trust("host:cc-1", &host.public_key);
    let mut sender = HeartbeatSender::new(
        "interlock:bench-1",
        "host:cc-1",
        EPOCH,
        SoftwareCounter::starting_at(1),
        &host.private_key,
    );
    let mut dog = Watchdog::new(config(), profile(1_000));
    let blind = HostSignal {
        observer: ObserverState::IntegrityUnknown,
        ..nominal()
    };
    let first = sender.next(blind, 0).unwrap();
    let first = verify_heartbeat(&first, &anchors).unwrap();
    assert_eq!(dog.arm(&first, 0), Err(ArmError::FirstHeartbeatNotNominal));
    assert!(!dog.actuator_permitted());
}

#[test]
fn t09_a_trip_is_absorbing_until_an_operator_resets() {
    let mut b = Bench::armed();
    let past = u64::from(PERIOD_MS) * (u64::from(TOLERATED_MISSES) + 1);
    assert!(matches!(b.dog.on_tick(past), HeartbeatOutcome::Tripped(_)));
    // A perfectly good heartbeat arrives. It changes nothing.
    assert_eq!(b.beat(nominal(), past + 1), HeartbeatOutcome::Ignored);
    assert!(!b.dog.actuator_permitted());
    // Arming from Tripped is refused; only an operator reset clears it.
    let hb = b.sender.next(nominal(), past + 2).unwrap();
    let hb = verify_heartbeat(&hb, &b.anchors).unwrap();
    assert_eq!(
        b.dog.arm(&hb, past + 2),
        Err(ArmError::TrippedRequiresOperatorReset)
    );
    b.dog.operator_reset();
    assert_eq!(b.dog.state(), WatchdogState::Disarmed);
    let hb = b.sender.next(nominal(), past + 3).unwrap();
    let hb = verify_heartbeat(&hb, &b.anchors).unwrap();
    assert_eq!(b.dog.arm(&hb, past + 3), Ok(()));
}

#[test]
fn t10_a_heartbeat_from_an_unanchored_sender_is_refused() {
    let b = Bench::armed();
    let mallory = generate_ed25519_keypair();
    let mut forged = HeartbeatSender::new(
        "interlock:bench-1",
        "host:cc-1", // claims the anchored name
        EPOCH,
        SoftwareCounter::starting_at(1_000),
        &mallory.private_key,
    );
    let hb = forged.next(nominal(), 100).unwrap();
    assert_eq!(
        verify_heartbeat(&hb, &b.anchors),
        Err(HeartbeatError::SignatureInvalid)
    );
    // And under a name nobody anchored, the verifier has no opinion at all.
    let mut unknown = HeartbeatSender::new(
        "interlock:bench-1",
        "host:nobody",
        EPOCH,
        SoftwareCounter::starting_at(1),
        &mallory.private_key,
    );
    let hb = unknown.next(nominal(), 100).unwrap();
    assert_eq!(
        verify_heartbeat(&hb, &b.anchors),
        Err(HeartbeatError::SenderNotAnchored("host:nobody".into()))
    );
}

#[test]
fn t11_every_non_active_observer_state_withholds_the_heartbeat() {
    let states = [
        (ObserverState::Degraded, 0x02),
        (ObserverState::Recovering, 0x03),
        (ObserverState::ContinuityUnverified, 0x04),
        (ObserverState::Quarantined, 0x05),
        (ObserverState::IntegrityUnknown, 0x06),
    ];
    for (state, code) in states {
        let signal = HostSignal {
            observer: state,
            ..nominal()
        };
        assert_eq!(
            signal.condition(),
            HostCondition::Withheld(WithholdReason::ObserverNotActive { state_code: code }),
            "{state:?} must withhold"
        );
        let mut b = Bench::armed();
        assert!(matches!(
            b.beat(signal, 100),
            HeartbeatOutcome::Tripped(TripReason::Withheld(WithholdReason::ObserverNotActive {
                state_code
            })) if state_code == code
        ));
    }
    assert_eq!(nominal().condition(), HostCondition::Nominal);
}

#[test]
fn t12_a_clock_that_goes_backwards_does_not_extend_permission() {
    let mut b = Bench::armed();
    assert_eq!(b.beat(nominal(), 500), HeartbeatOutcome::Accepted);
    // The interlock's clock is adjusted to before the last accepted beat.
    assert!(matches!(
        b.dog.on_tick(100),
        HeartbeatOutcome::Tripped(TripReason::Silence { .. })
    ));
}

#[test]
fn t13_a_measurement_verifies_under_the_board_key_and_not_under_the_host_key() {
    let board = generate_ed25519_keypair();
    let host = generate_ed25519_keypair();
    let anchors = InterlockAnchors::new()
        .trust("interlock:bench-1", &board.public_key)
        .trust("host:cc-1", &host.public_key);
    let m = InterlockMeasurement {
        version: INTERLOCK_MEASUREMENT_VERSION,
        interlock_id: "interlock:bench-1".into(),
        actuator_id: "arm-joint-3".into(),
        channel: SenseChannel::CurrentMilliamps,
        value: 0, // the robot said it moved; no current flowed
        at_counter: 42,
        sampled_at_ms: 7_000,
    };
    let good = SignedInterlockMeasurement::sign(m.clone(), &board.private_key).unwrap();
    assert_eq!(verify_measurement(&good, &anchors), Ok(&m));

    // The host signing a reading about the board's channel is exactly the
    // self-report the board exists to be independent of.
    let mut forged = SignedInterlockMeasurement::sign(m.clone(), &host.private_key).unwrap();
    assert_eq!(
        verify_measurement(&forged, &anchors),
        Err(MeasurementError::SignatureInvalid)
    );
    forged.attestation.signer_id = "host:cc-1".into();
    assert_eq!(
        verify_measurement(&forged, &anchors),
        Err(MeasurementError::SignerIsNotBoard)
    );
}

#[test]
fn t14_this_crate_does_not_reach_the_observation_or_reconciliation_path() {
    // ADR-008 §5.1: nothing in the interlock tier feeds observation, and a
    // measurement is not an ObservationRecord until aip-observation grows a
    // mechanism for it. Pinned at the manifest so it cannot drift silently.
    let manifest =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    for forbidden in [
        "aip-observation",
        "aip-reconcile",
        "aip-warrant",
        "aip-containment",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "aip-interlock must not depend on {forbidden}"
        );
    }
}

#[test]
fn t15_disarming_does_not_clear_a_trip() {
    let mut b = Bench::armed();
    let past = u64::from(PERIOD_MS) * (u64::from(TOLERATED_MISSES) + 1);
    assert!(matches!(b.dog.on_tick(past), HeartbeatOutcome::Tripped(_)));
    b.dog.disarm();
    assert!(matches!(b.dog.state(), WatchdogState::Tripped { .. }));
}

#[test]
fn t16_a_software_counter_that_cannot_advance_refuses_rather_than_repeats() {
    let host = generate_ed25519_keypair();
    let mut sender = HeartbeatSender::new(
        "interlock:bench-1",
        "host:cc-1",
        EPOCH,
        SoftwareCounter::starting_at(u64::MAX - 1),
        &host.private_key,
    );
    // u64::MAX - 1 is emitted; u64::MAX never is, because the counter refuses
    // to hand out a value it could not follow with a strictly greater one.
    assert!(sender.next(nominal(), 0).is_ok());
    assert_eq!(
        sender.next(nominal(), 1).err(),
        Some(SenderError::Counter(CounterError::Exhausted))
    );
}
