//! Gate 8 — a collector *process* over a state directory.
//! NOT_PRODUCTION_CAPABILITY.
//!
//!     ghost-demo-collector --dir D --observer ID --batches N [--strict]
//!
//! Starts a `CollectorRuntime` over `D`, attests `N` empty batches with a
//! health record after each, prints what happened, and exits. Run twice
//! over the same directory it continues one chain; run over a rolled-back
//! state file in strict mode it refuses (exit 3) and leaves a signed
//! report.
//!
//! The keypair is generated on first run and written to `D` in plaintext,
//! which is exactly what a production collector must never do: the point
//! of the architecture is that the key is off the observed host. This
//! binary exists to restart a process, not to model key custody.

use std::path::PathBuf;

use aip_observe::{
    CollectorRuntime, CollectorStore, ContinuityBreak, ContinuityPolicy, ProcfsProbe, StartOutcome,
    Started,
};

const KEY_FILE: &str = "NOT_PRODUCTION.collector.key.hex";
const OBSERVE_ID_DEFAULT: &str = "demo-collector";

struct Args {
    dir: PathBuf,
    observer: String,
    batches: u8,
    strict: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut dir = None;
    let mut observer = OBSERVE_ID_DEFAULT.to_string();
    let mut batches = 1u8;
    let mut strict = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--dir" => dir = Some(PathBuf::from(it.next().ok_or("--dir needs a path")?)),
            "--observer" => observer = it.next().ok_or("--observer needs an id")?,
            "--batches" => {
                batches = it
                    .next()
                    .ok_or("--batches needs a count")?
                    .parse()
                    .map_err(|e| format!("--batches: {e}"))?
            }
            "--strict" => strict = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(Args {
        dir: dir.ok_or("--dir is required")?,
        observer,
        batches,
        strict,
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Load or create the demonstrator keypair: `<private hex>\n<public hex>\n`.
fn keypair(dir: &std::path::Path) -> Result<(Vec<u8>, Vec<u8>), String> {
    let path = dir.join(KEY_FILE);
    if let Ok(text) = std::fs::read_to_string(&path) {
        let mut lines = text.lines();
        let sk = lines
            .next()
            .and_then(unhex)
            .ok_or("key file: bad private line")?;
        let pk = lines
            .next()
            .and_then(unhex)
            .ok_or("key file: bad public line")?;
        return Ok((sk, pk));
    }
    let kp = aip_crypto::generate_ed25519_keypair();
    std::fs::write(
        &path,
        format!("{}\n{}\n", hex(&kp.private_key), hex(&kp.public_key)),
    )
    .map_err(|e| e.to_string())?;
    Ok((kp.private_key, kp.public_key))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn break_name(b: &ContinuityBreak) -> &'static str {
    match b {
        ContinuityBreak::Amnesia { .. } => "Amnesia",
        ContinuityBreak::RolledBack { .. } => "RolledBack",
        ContinuityBreak::Forked { .. } => "Forked",
        ContinuityBreak::ArchiveTruncated { .. } => "ArchiveTruncated",
    }
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    std::fs::create_dir_all(&args.dir).expect("state dir");
    let (sk, pk) = match keypair(&args.dir) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let policy = if args.strict {
        ContinuityPolicy::Strict
    } else {
        ContinuityPolicy::Advisory
    };
    let store = CollectorStore::open(&args.dir).expect("open store");
    let started = match CollectorRuntime::start(store, &args.observer, 1, &sk, &pk, policy) {
        Ok(s) => s,
        Err(e) => {
            println!("started=error:{e}");
            std::process::exit(4);
        }
    };
    let (mut rt, outcome) = match started {
        Started::Running(rt, outcome) => (rt, outcome),
        Started::Refused(b) => {
            println!("started=refused:{}", break_name(&b));
            println!("policy={policy:?}");
            std::process::exit(3);
        }
    };
    match &outcome {
        StartOutcome::Fresh => println!("started=fresh"),
        StartOutcome::Resumed {
            continuity_break: None,
        } => println!("started=resumed"),
        StartOutcome::Resumed {
            continuity_break: Some(b),
        } => println!("started=resumed-with-break:{}", break_name(b)),
    }
    println!("policy={policy:?}");
    println!("state-at-start={:?}", rt.state());

    let mut probe = ProcfsProbe::new("demo-probe");
    let mut last = None;
    for _ in 0..args.batches {
        let t = now_ms();
        let batch = probe.batch(aip_core::capability::random_jti(), t, t, vec![]);
        match rt.attest_at(batch, t) {
            Ok(a) => last = Some(a.head()),
            Err(e) => {
                println!("attest=error:{e}");
                break;
            }
        }
        if let Err(e) = rt.health(now_ms()) {
            println!("health=error:{e}");
            break;
        }
    }
    let snap = rt.snapshot();
    println!("sequence={}", snap.sequence.unwrap_or(0));
    println!(
        "head={}",
        last.or(snap.head).map(|h| hex(&h)).unwrap_or_default()
    );
    println!("state-at-end={:?}", rt.state());
}
