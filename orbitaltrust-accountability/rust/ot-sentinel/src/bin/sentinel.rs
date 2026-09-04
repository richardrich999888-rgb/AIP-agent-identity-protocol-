//! The Agent Sentinel, as a process.
//!
//! ```text
//! sentinel --ledger evidence.jsonl --access-log access.jsonl \
//!          --state sentinel-state.json --archive sentinel-archive.jsonl \
//!          --covers send_command --trust-sensors --interval 60
//! ```
//!
//! All detection logic lives in the library ([`ot_sentinel::runtime`]); this
//! binary only parses arguments, owns the loop and the clock, and prints.
//! Exit codes: 0 clean run, 1 configuration error, 2 the startup continuity
//! audit found a break and `--strict-continuity` was set.

use std::process::exit;

use ot_sentinel::conformance::EffectPolicy;
use ot_sentinel::response::ResponsePolicy;
use ot_sentinel::runtime::{now_iso8601, RuntimeConfig, SentinelRuntime};

const USAGE: &str = "\
sentinel — the OrbitalTrust out-of-band agent watchdog

REQUIRED
  --ledger <path>           evidence ledger the gateway writes (JSONL)

SENSORS (at least one is useful; none still audits the ledger itself)
  --access-log <path>       tool-server access log to tail
  --effect-log <path>       egress/process-spawn log to tail
  --covers <tool>           tool the access log fully covers (repeatable)
  --trust-sensors           operator vouches for the tailed sensors

DURABILITY
  --state <path>            patrol state file      [sentinel-state.json]
  --archive <path>          own-anchor archive     [sentinel-archive.jsonl]
  --strict-continuity       exit 2 instead of running when the startup
                            audit finds a continuity break

POLICY (advisory unless told otherwise)
  --autonomous              containment on Proof-strength findings
  --allow-dest <host>       approved egress destination (repeatable;
                            first use turns fail-closed egress checking on)
  --allow-cmd <command>     sanctioned process command (repeatable;
                            first use turns fail-closed spawn checking on)

LOOP
  --interval <seconds>      patrol cadence         [60]
  --once                    one cycle, then exit
  --deep-verify-every <n>   full re-hash cadence   [10]
  --did <did>               sentinel identity      [did:syntriass:sentinel:LOCAL-1]
";

fn main() {
    let mut args = std::env::args().skip(1);
    let mut ledger = None;
    let mut access_log = None;
    let mut effect_log = None;
    let mut state_path = "sentinel-state.json".to_string();
    let mut archive_path = "sentinel-archive.jsonl".to_string();
    let mut did = "did:syntriass:sentinel:LOCAL-1".to_string();
    let mut interval = 60u64;
    let mut once = false;
    let mut deep_verify_every = 10u64;
    let mut autonomous = false;
    let mut trust_sensors = false;
    let mut strict_continuity = false;
    let mut covers: Vec<String> = Vec::new();
    let mut effect_policy: Option<EffectPolicy> = None;

    let missing = |flag: &str| -> String {
        eprintln!("{flag} needs a value\n\n{USAGE}");
        exit(1);
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--ledger" => ledger = Some(args.next().unwrap_or_else(|| missing("--ledger"))),
            "--access-log" => {
                access_log = Some(args.next().unwrap_or_else(|| missing("--access-log")))
            }
            "--effect-log" => {
                effect_log = Some(args.next().unwrap_or_else(|| missing("--effect-log")))
            }
            "--state" => state_path = args.next().unwrap_or_else(|| missing("--state")),
            "--archive" => archive_path = args.next().unwrap_or_else(|| missing("--archive")),
            "--did" => did = args.next().unwrap_or_else(|| missing("--did")),
            "--covers" => covers.push(args.next().unwrap_or_else(|| missing("--covers"))),
            "--interval" => match args.next().and_then(|v| v.parse().ok()) {
                Some(seconds) => interval = seconds,
                None => {
                    eprintln!("--interval needs a number of seconds\n\n{USAGE}");
                    exit(1);
                }
            },
            "--deep-verify-every" => match args.next().and_then(|v| v.parse().ok()) {
                Some(cycles) => deep_verify_every = cycles,
                None => {
                    eprintln!("--deep-verify-every needs a cycle count\n\n{USAGE}");
                    exit(1);
                }
            },
            "--allow-dest" => {
                let host = args.next().unwrap_or_else(|| missing("--allow-dest"));
                effect_policy = Some(effect_policy.unwrap_or_default().allow_destination(&host));
            }
            "--allow-cmd" => {
                let command = args.next().unwrap_or_else(|| missing("--allow-cmd"));
                effect_policy = Some(effect_policy.unwrap_or_default().allow_command(&command));
            }
            "--once" => once = true,
            "--autonomous" => autonomous = true,
            "--trust-sensors" => trust_sensors = true,
            "--strict-continuity" => strict_continuity = true,
            "--help" | "-h" => {
                println!("{USAGE}");
                return;
            }
            other => {
                eprintln!("unknown argument {other}\n\n{USAGE}");
                exit(1);
            }
        }
    }
    let Some(ledger) = ledger else {
        eprintln!("--ledger is required\n\n{USAGE}");
        exit(1);
    };

    let config = RuntimeConfig {
        sentinel_did: did,
        ledger_path: ledger.into(),
        access_log: access_log.map(Into::into),
        effect_log: effect_log.map(Into::into),
        state_path: state_path.into(),
        archive_path: archive_path.into(),
        deep_verify_every,
        policy: if autonomous {
            ResponsePolicy::autonomous()
        } else {
            ResponsePolicy::default()
        },
        effect_policy,
        trust_sensors,
        covered_tools: covers,
    };

    let (mut runtime, continuity_break) = match SentinelRuntime::start(config) {
        Ok(started) => started,
        Err(why) => {
            eprintln!("sentinel refused to start: {why}");
            exit(1);
        }
    };

    println!("OrbitalTrust Agent Sentinel — {}", runtime.sentinel_did());
    if let Some(break_) = &continuity_break {
        eprintln!("CONTINUITY {}: {}", break_.as_str(), break_.summary());
        if strict_continuity {
            exit(2);
        }
        eprintln!("running anyway — every patrol will carry this finding");
    }

    loop {
        let now = now_iso8601();
        match runtime.run_cycle(&now) {
            Ok(cycle) => {
                println!("[{now}] {}", cycle.report.headline());
                for finding in &cycle.report.findings {
                    println!(
                        "  {} {} [{}·{}] {}",
                        finding.kind.as_str(),
                        finding.subject_did.as_deref().unwrap_or("-"),
                        finding.severity.as_str(),
                        finding.strength.as_str(),
                        finding.summary,
                    );
                }
                for action in cycle.report.containments() {
                    println!(
                        "  CONTAINMENT {} -> {}",
                        action.response.as_str(),
                        action.subject_did.as_deref().unwrap_or("-"),
                    );
                }
            }
            // One failed cycle is reported, not fatal: the durable state is
            // only written on success, so the next cycle retries cleanly.
            Err(why) => eprintln!("[{now}] cycle failed: {why}"),
        }
        if once {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(interval.max(1)));
    }
}
