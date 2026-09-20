//! REFERENCE TRANSPORT — **not** a production transport.
//!
//! # What this module is, and the mistake it is written to prevent
//!
//! The reference moves three kinds of bytes between three processes: commands
//! down a pipe, replies back up it, and signed artifacts through JSON Lines in
//! a state directory. All of it is here, in one adapter module, so that a
//! reader can see the entire transport surface at once and confirm that
//! **nothing above it depends on any of it**.
//!
//! That is the point. `aip-observe`, `aip-observation`, `aip-platform` and
//! `aip-effect` do not know these bytes exist. The security property of an
//! `AttestedBatch` is the collector's signature over its canonical preimage,
//! and that property survives any carrier: a pipe, a file, a queue, a TLS
//! socket, a courier with a USB stick. A transport cannot add to it and,
//! short of losing bytes, cannot subtract from it either.
//!
//! So this choice is a *reference* choice, made for three properties a
//! demonstration needs and a deployment does not care about:
//!
//! | property | why the reference wants it |
//! |---|---|
//! | synchronous request/reply | the driver can place kernel activity exactly between two batch boundaries, so no test contains a sleep or a retry |
//! | ordered append-only files | the batch chain on disk is in attestation order, so a continuity break is visible by reading the file |
//! | no daemon, no network | the reference runs on a bare host and in CI without provisioning |
//!
//! A production deployment moves batches off the observed host by whatever
//! authenticated means it already operates. Nothing here is a protocol
//! requirement, and no new network protocol is introduced by Skill 22.
//!
//! # What the transport is *not* trusted for
//!
//! Nothing. A JSON line that does not deserialize is dropped and counted; a
//! line that does deserialize is still only a candidate until
//! `verify_attested_batch` accepts it. The reader below therefore returns
//! parsed values and never a judgement, and no function in this module takes a
//! trust anchor — because a transport that could verify would be a transport
//! that could be persuaded not to.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};

use aip_edge_contract as contract;
use aip_observe::{AttestedBatch, SignedSensorHealth};

use crate::error::EdgeError;

/// Read every JSON Lines record of one type from `path`.
///
/// A line that fails to parse is **skipped and counted**, never guessed at:
/// the count is returned so a caller can distinguish "the file was empty" from
/// "the file was corrupt", which are different operational facts. Nothing here
/// verifies anything.
pub fn read_jsonl<T: serde::de::DeserializeOwned>(
    path: &Path,
) -> Result<(Vec<T>, usize), EdgeError> {
    let file = std::fs::File::open(path)
        .map_err(|e| EdgeError::Transport(format!("{}: {e}", path.display())))?;
    let mut out = Vec::new();
    let mut malformed = 0usize;
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|e| EdgeError::Transport(format!("{}: {e}", path.display())))?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<T>(&line) {
            Ok(v) => out.push(v),
            Err(_) => malformed += 1,
        }
    }
    Ok((out, malformed))
}

/// Read one JSON value from `path`.
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, EdgeError> {
    let bytes = std::fs::read(path)
        .map_err(|e| EdgeError::Transport(format!("{}: {e}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| EdgeError::Transport(format!("{}: {e}", path.display())))
}

/// The batches the observer has attested so far, in attestation order.
pub fn read_batches(dir: &Path) -> Result<Vec<AttestedBatch>, EdgeError> {
    let (v, malformed) = read_jsonl::<AttestedBatch>(&dir.join(contract::BATCHES_JSONL))?;
    if malformed > 0 {
        return Err(EdgeError::Transport(format!(
            "{malformed} malformed line(s) in {}; refusing a partial batch chain",
            contract::BATCHES_JSONL
        )));
    }
    Ok(v)
}

/// The signed health records the observer has emitted so far.
pub fn read_health(dir: &Path) -> Result<Vec<SignedSensorHealth>, EdgeError> {
    let (v, malformed) = read_jsonl::<SignedSensorHealth>(&dir.join(contract::HEALTH_JSONL))?;
    if malformed > 0 {
        return Err(EdgeError::Transport(format!(
            "{malformed} malformed line(s) in {}",
            contract::HEALTH_JSONL
        )));
    }
    Ok(v)
}

/// A child process driven by the one-line request/reply protocol.
///
/// Holding one of these is the reference's way of saying "this is a separate
/// OS process". The driver has a pipe and a pid; it does not have the child's
/// memory, its keys, or a function call into it.
pub struct Peer {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    label: &'static str,
}

impl Peer {
    /// Spawn `binary` with `args`, wired for the line protocol.
    pub fn spawn(label: &'static str, binary: &Path, args: &[&str]) -> Result<Self, EdgeError> {
        let mut child = Command::new(binary)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| {
                EdgeError::Transport(format!("spawn {label} at {}: {e}", binary.display()))
            })?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        Ok(Self {
            child,
            stdin,
            stdout,
            label,
        })
    }

    /// The child's pid **as the operating system reports it to the parent**.
    ///
    /// Not a claim by the child. The driver uses this to tell the observer
    /// which instance to look at, and separately compares it with the pid the
    /// workload reported about itself — a comparison that is only meaningful
    /// because the two numbers come from different places.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Send one command and block for its reply.
    ///
    /// Blocking is the feature. It is what lets the driver guarantee that the
    /// connection existed before the observer looked, without a sleep and
    /// without a retry loop, which is what makes the reference deterministic.
    pub fn command(&mut self, line: &str) -> Result<String, EdgeError> {
        writeln!(self.stdin, "{line}")
            .map_err(|e| EdgeError::Transport(format!("{}: write: {e}", self.label)))?;
        self.stdin
            .flush()
            .map_err(|e| EdgeError::Transport(format!("{}: flush: {e}", self.label)))?;
        let mut reply = String::new();
        let n = self
            .stdout
            .read_line(&mut reply)
            .map_err(|e| EdgeError::Transport(format!("{}: read: {e}", self.label)))?;
        if n == 0 {
            return Err(EdgeError::Transport(format!(
                "{}: closed its output before replying to {line:?}",
                self.label
            )));
        }
        let reply = reply.trim().to_string();
        match reply.strip_prefix(&format!("{} ", contract::REPLY_OK)) {
            Some(rest) => Ok(rest.to_string()),
            None => Err(EdgeError::Transport(format!("{}: {reply}", self.label))),
        }
    }

    /// Ask the child to exit, then wait for it.
    pub fn quit(mut self) -> Result<(), EdgeError> {
        let _ = self.command(contract::CMD_QUIT);
        drop(self.stdin);
        self.child
            .wait()
            .map_err(|e| EdgeError::Transport(format!("{}: wait: {e}", self.label)))?;
        Ok(())
    }

    /// Kill the child without asking — used to exercise observer loss and
    /// workload loss, where a clean shutdown would be the wrong stimulus.
    pub fn kill(mut self) -> Result<(), EdgeError> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        Ok(())
    }
}

/// Locate a sibling workspace binary next to the running executable.
///
/// Cargo exposes `CARGO_BIN_EXE_*` only for binaries of the package under
/// test, and moving the workload and observer into this package would destroy
/// the dependency isolation the reference exists to demonstrate. So they are
/// found on disk, exactly as `ghost-demo` finds its agent.
///
/// Returns a descriptive error rather than skipping: a reference that quietly
/// does nothing when its own binaries are missing is worse than one that stops
/// and says which command builds them.
/// The sibling binaries the orchestrator spawns, by package name.
pub const SIBLING_BINARIES: [&str; 2] = ["aip-edge-observer", "aip-edge-workload"];

/// Build the sibling binaries the orchestrator spawns, with the cargo and
/// profile that built the caller, into the target directory
/// [`sibling_binary`] searches.
///
/// # Why a library function and not a test helper
///
/// `cargo test --workspace` compiles a package's binaries only when that
/// package has integration tests of its own, and `aip-edge-observer` and
/// `aip-edge-workload` have none. Every crate that drives the reference —
/// `aip-edge`, and the robotics, industrial, space, UAS and enterprise
/// profiles — therefore depends on something else having built them first.
/// A copy of this logic in each test harness is five copies to keep correct,
/// and the profiles had none: their tests passed only when `aip-edge`'s tests
/// happened to run first in the same invocation.
///
/// # Why it rebuilds rather than checking for existence
///
/// An earlier version built only the binaries that were *missing*. That left
/// the worse failure in place: a binary present but built before a protocol
/// change is found, spawned, and produces records the current engine refuses,
/// so the test fails with an evidence error that has nothing to do with
/// evidence. `cargo build` is a no-op when the binaries are current and the
/// correct action when they are not, so it is always run.
///
/// Once per process. Returns a descriptive error rather than skipping: a
/// reference that quietly does nothing when its own binaries are absent is
/// worse than one that stops and names the command that builds them.
pub fn ensure_sibling_binaries() -> Result<(), EdgeError> {
    static BUILT: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(build_sibling_binaries)
        .clone()
        .map_err(EdgeError::Transport)
}

fn build_sibling_binaries() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    // `<target>/<profile>/deps/<test>` for a test binary, `<target>/<profile>/<bin>`
    // for a binary. The profile directory is the one holding `deps`, so walk
    // up until a directory named `deps` is passed, at most one level.
    let mut profile_dir = exe
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", exe.display()))?
        .to_path_buf();
    if profile_dir.file_name().is_some_and(|n| n == "deps") {
        profile_dir = profile_dir
            .parent()
            .ok_or_else(|| "deps directory has no parent".to_string())?
            .to_path_buf();
    }
    let target_dir = profile_dir
        .parent()
        .ok_or_else(|| format!("{} has no target directory", profile_dir.display()))?
        .to_path_buf();
    let release = profile_dir.file_name().is_some_and(|p| p == "release");

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = std::process::Command::new(cargo);
    cmd.arg("build").arg("--target-dir").arg(&target_dir);
    if release {
        cmd.arg("--release");
    }
    for name in SIBLING_BINARIES {
        cmd.arg("-p").arg(name);
    }
    let status = cmd
        .status()
        .map_err(|e| format!("could not run cargo to build {SIBLING_BINARIES:?}: {e}"))?;
    if !status.success() {
        return Err(format!(
            "building {SIBLING_BINARIES:?} failed; from a shell: cargo build -p {} -p {}",
            SIBLING_BINARIES[0], SIBLING_BINARIES[1]
        ));
    }
    for name in SIBLING_BINARIES {
        if !profile_dir.join(name).exists() {
            return Err(format!(
                "{name} was built but did not appear in {}",
                profile_dir.display()
            ));
        }
    }
    Ok(())
}

pub fn sibling_binary(name: &str) -> Result<PathBuf, EdgeError> {
    let exe =
        std::env::current_exe().map_err(|e| EdgeError::Transport(format!("current_exe: {e}")))?;
    let mut dir = exe.parent().map(Path::to_path_buf);
    // `target/debug/deps/<test>` and `target/debug/<bin>` are both possible
    // homes for the caller, so try this directory and its parent.
    for _ in 0..2 {
        let Some(d) = dir else { break };
        let candidate = d.join(name);
        if candidate.exists() {
            return Ok(candidate);
        }
        dir = d.parent().map(Path::to_path_buf);
    }
    // `cargo test --workspace` does not build it: a package's binaries are
    // compiled for tests only when that package has integration tests of
    // its own, and the sibling packages have none. The reference test
    // harness builds them on demand; from a shell it is one command.
    Err(EdgeError::Transport(format!(
        "{name} was not found next to {}; build it with `cargo build -p {name}`",
        exe.display()
    )))
}
