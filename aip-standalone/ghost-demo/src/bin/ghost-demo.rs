//! Human-runnable end-to-end demonstrator. NOT_PRODUCTION_CAPABILITY.
//!
//!     cargo run -p ghost-demo --bin ghost-demo
//!
//! Spawns the controlled agent (`ghost-demo-agent`, built alongside), runs
//! the positive scenario and negatives A–G on this Linux host, and prints
//! each reconciliation. Requires procfs, pidfd_open and readable
//! `/proc/net/tcp`.

fn main() {
    let agent_bin = std::env::current_exe()
        .expect("current exe")
        .parent()
        .expect("bin dir")
        .join("ghost-demo-agent");
    let agent_bin = agent_bin.to_string_lossy().into_owned();
    if !std::path::Path::new(&agent_bin).exists() {
        eprintln!("agent binary not found at {agent_bin}; build with `cargo build -p ghost-demo`");
        std::process::exit(2);
    }
    println!("ghost-demo — action-level evidence, live (NOT_PRODUCTION_CAPABILITY)");
    println!("agent binary: {agent_bin}");
    println!();
    let (demos, skipped) = ghost_demo::run_all(&agent_bin);
    for (s, why) in &skipped {
        println!(
            "{} — SKIPPED: kernel socket-state source unavailable: {why}",
            s.label()
        );
        println!();
    }
    for demo in demos {
        let r = &demo.reconciliation;
        println!("{}", demo.scenario.label());
        println!("    {}", demo.note);
        println!(
            "    result={} strength={:?} reason={:?}",
            r.result.as_str(),
            r.strength,
            r.reason
        );
        println!(
            "    identity={:?} action={:?} temporal={:?} replay_detected={}",
            r.identity, r.action, r.temporal, r.replay_detected
        );
        println!("    availability={:?}", r.availability);
        println!();
    }
    println!(
        "Nothing above proves payload or bytes, or anything a root host could not have written"
    );
    println!(
        "into procfs or suppressed in the perf ring. Positive results are Attested, never Proven."
    );
    println!(
        "Presence evidence shows a connection existed at the sample; transition evidence shows"
    );
    println!("the kernel reported it being made, placed in time by signed collector and anchored");
    println!("kernel clocks.");
}
