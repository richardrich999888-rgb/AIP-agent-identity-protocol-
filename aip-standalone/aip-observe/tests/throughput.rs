//! What the accountability layer costs, measured rather than asserted.
//!
//! # Why this exists
//!
//! The technical brief declined to quote any performance figure on the
//! grounds that none had been measured. That was true of the observer path
//! and it is a defensible refusal, but it is not a good one: an institution
//! deciding whether to put this in front of a workload needs an order of
//! magnitude, and "we have not measured it" invites the reader to assume the
//! worst or, worse, to assume nothing. The evidence vault already had
//! measurements (`docs/STORAGE_PERFORMANCE.md`); the observer did not.
//!
//! # What is measured, and what these numbers are not
//!
//! Three costs on the signing and verification path, each in isolation:
//!
//! 1. **Canonical encoding** — turning a batch into the bytes that get
//!    hashed. No cryptography. This is the floor.
//! 2. **Attestation** — `CollectorRuntime::attest`: encode, hash, sign with
//!    Ed25519, advance the chain, persist the position. This is the
//!    collector's per-batch cost and the one that bounds how many observed
//!    hosts one collector can serve.
//! 3. **Offline verification** — `verify_attested_batch`: re-encode,
//!    re-hash, check the Ed25519 signature. This is the auditor's cost per
//!    record, and it bounds how long verifying a retained archive takes.
//!
//! These are **not** a claim about a production deployment. They exclude the
//! network, the probe's own sampling cost, and the disk the archive lands on,
//! and they were taken on whatever machine ran them. The output prints the
//! host so a number is never quoted without the machine it came from.
//!
//! # Determinism
//!
//! Iteration counts are fixed constants, the input batches are built to a
//! fixed shape from a fixed seed sequence, and percentiles come from the
//! sorted sample rather than from a sampling estimator. The one source of
//! nondeterminism is the Ed25519 signature nonce, which is drawn from the OS
//! and does not affect the cost of signing. Nothing here is randomised for
//! statistical purposes, because a benchmark that samples differently on
//! every run cannot be compared between two commits.
//!
//! Run:
//! ```text
//! cargo test --release -p aip-observe --test throughput -- --ignored --nocapture
//! ```
//! It is `#[ignore]`d because a timing measurement inside the ordinary test
//! run would be a flaky assertion: the suite must not fail because the
//! machine was busy.

use std::time::{Duration, Instant};

use aip_observe::{
    verify_attested_batch, AttestedBatch, CollectorKey, CollectorRuntime, CollectorStore,
    ContinuityPolicy, ObservationBatch, ObserverTrustAnchors, ProcfsProbe, Started,
};

/// Batches attested and then verified. Large enough that per-iteration noise
/// averages out, small enough that the whole run stays under a minute on a
/// modest machine.
const N: usize = 2_000;
/// Discarded before measurement so page faults on first touch and any
/// first-call initialisation do not land in the sample.
const WARMUP: usize = 100;

const OBSERVER_ID: &str = "collector.bench";
const KEY_VERSION: u32 = 1;

/// Sorted latency samples, so every statistic below is exact rather than
/// estimated.
struct Samples(Vec<Duration>);

impl Samples {
    fn new(mut v: Vec<Duration>) -> Self {
        v.sort_unstable();
        Self(v)
    }

    /// Nearest-rank percentile: the smallest sample at or above the given
    /// fraction of the population. No interpolation, so the value printed is
    /// one that actually occurred.
    fn pct(&self, p: f64) -> Duration {
        debug_assert!((0.0..=1.0).contains(&p));
        if self.0.is_empty() {
            return Duration::ZERO;
        }
        let rank = ((p * self.0.len() as f64).ceil() as usize).max(1);
        self.0[rank.min(self.0.len()) - 1]
    }

    fn total(&self) -> Duration {
        self.0.iter().sum()
    }

    fn mean(&self) -> Duration {
        if self.0.is_empty() {
            Duration::ZERO
        } else {
            self.total() / self.0.len() as u32
        }
    }

    /// Operations per second derived from the summed sample time, not from
    /// wall-clock around the loop: the loop also builds inputs, and charging
    /// that to the operation would understate it.
    fn per_second(&self) -> f64 {
        let t = self.total().as_secs_f64();
        if t <= 0.0 {
            f64::INFINITY
        } else {
            self.0.len() as f64 / t
        }
    }

    fn report(&self, what: &str) {
        println!(
            "  {what:<26} {:>9.0}/s   mean {:>8.1} us   p50 {:>8.1}   p95 {:>8.1}   \
             p99 {:>8.1}   max {:>8.1}",
            self.per_second(),
            us(self.mean()),
            us(self.pct(0.50)),
            us(self.pct(0.95)),
            us(self.pct(0.99)),
            us(self.pct(1.00)),
        );
    }
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aip-observe-bench-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A fixed-shape batch. `i` only varies the batch id and the claimed window,
/// so every iteration encodes the same number of bytes and the measurement is
/// of one operation rather than of a distribution of input sizes.
fn batch(probe: &mut ProcfsProbe, i: usize) -> ObservationBatch {
    let base = 1_000_000 + (i as u64) * 1_000;
    probe.batch([(i % 256) as u8; 16], base, base + 500, vec![])
}

fn host_line() -> String {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    let model = std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()))
        .unwrap_or_else(|| "unknown CPU".into());
    let profile = if cfg!(debug_assertions) {
        "debug (UNOPTIMISED — do not quote these numbers)"
    } else {
        "release"
    };
    format!("kernel {kernel}, {cpus} CPU, {model}, {profile} build")
}

#[test]
#[ignore = "timing measurement; run explicitly with --release --nocapture"]
fn observer_path_throughput() {
    println!("\nObserver path, measured on: {}", host_line());
    println!("N = {N} batches ({WARMUP} discarded as warm-up)\n");

    let dir = scratch("throughput");
    let store = CollectorStore::open(&dir).unwrap();
    let key = CollectorKey::development();
    let public_key = key.public_key().to_vec();
    let started = CollectorRuntime::start_with_custodian(
        store,
        OBSERVER_ID,
        KEY_VERSION,
        key.into_custodian(),
        ContinuityPolicy::Strict,
    )
    .unwrap();
    let mut rt = match started {
        Started::Running(rt, _) => rt,
        Started::Refused(b) => panic!("fresh runtime refused: {b:?}"),
    };
    let mut probe = ProcfsProbe::new("probe.bench");

    // ── 1. Canonical encoding, the floor ─────────────────────────────────
    let sample = batch(&mut probe, 0);
    let encoded_len = sample.canonical_bytes().len();
    for i in 0..WARMUP {
        std::hint::black_box(batch(&mut probe, i).canonical_bytes());
    }
    let mut encode = Vec::with_capacity(N);
    for i in 0..N {
        let b = batch(&mut probe, i);
        let t = Instant::now();
        let bytes = b.canonical_bytes();
        encode.push(t.elapsed());
        std::hint::black_box(bytes);
    }
    let encode = Samples::new(encode);

    // ── 2. Attestation: encode, hash, sign, advance, persist ─────────────
    for i in 0..WARMUP {
        let b = batch(&mut probe, i);
        rt.attest(b).unwrap();
    }
    let mut attest = Vec::with_capacity(N);
    let mut attested: Vec<AttestedBatch> = Vec::with_capacity(N);
    for i in 0..N {
        let b = batch(&mut probe, i);
        let t = Instant::now();
        let a = rt.attest(b).unwrap();
        attest.push(t.elapsed());
        attested.push(a);
    }
    let attest = Samples::new(attest);

    // ── 3. Offline verification, the auditor's cost ──────────────────────
    let anchors = ObserverTrustAnchors::new().trust(OBSERVER_ID, KEY_VERSION, &public_key);
    for a in attested.iter().take(WARMUP.min(attested.len())) {
        verify_attested_batch(a, &anchors).unwrap();
    }
    let mut verify = Vec::with_capacity(N);
    for a in &attested {
        let t = Instant::now();
        let r = verify_attested_batch(a, &anchors);
        verify.push(t.elapsed());
        r.unwrap();
    }
    let verify = Samples::new(verify);

    println!("  batch canonical size: {encoded_len} bytes");
    encode.report("canonical encoding");
    attest.report("attest (sign + chain)");
    verify.report("verify (offline)");

    // The two numbers an operator actually plans with. Printed rather than
    // asserted, because the acceptable threshold is the institution's and
    // not ours.
    //
    // Archive verification: a retained archive is verified record by record,
    // so the auditor's wall-clock is simply the mean times the record count.
    let million = verify.mean() * 1_000_000;
    println!(
        "\n  verifying 1,000,000 archived batches at this rate: {:.1} s single-threaded",
        million.as_secs_f64()
    );
    // Collector fan-out: at the pilot's one-batch-per-second probe interval,
    // one probe costs one attestation per second, so the sustainable host
    // count equals the attestation rate. Stated as the arithmetic it is --
    // it is an upper bound on one axis, not a capacity figure.
    println!(
        "  attestation sustains ~{rate:.0} batches/s single-threaded; at the pilot's\n  \
         1 s batch interval that is an upper bound of ~{rate:.0} observed hosts per\n  \
         collector before attestation itself binds. Network, disk and lock\n  \
         contention are excluded and will bind first.",
        rate = attest.per_second()
    );
    println!(
        "\n  These are single-threaded, in-process, loopback-free figures on the host\n  \
         named above. They exclude the network, the probe's sampling cost and the\n  \
         disk the archive lands on. They are a floor for planning, not a service\n  \
         level, and no figure here should be quoted without the host line.\n"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
