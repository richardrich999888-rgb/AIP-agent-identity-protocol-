//! Model-server supervisor: verified start, serving profiles, on-demand load.
//!
//! Profiles encode measured trade-offs on the 2-vCPU research host
//! (research/compute-memory/LLM_EXPERIMENTS.md, native build, ctx 4096):
//!
//! | profile  | weights | repack | peak RSS | prefill @1.5k | decode | resident |
//! |----------|---------|--------|----------|---------------|--------|----------|
//! | memory   | Q4_K_M  | off    | ~1.3 GB  | ~35 tok/s     | ~10    | no (load on demand) |
//! | balanced | Q4_K_M  | on     | ~2.1 GB  | ~88 tok/s     | ~11    | yes |
//! | speed    | Q8_0    | on     | ~3.6 GB  | ~118 tok/s    | ~14    | yes |
//!
//! Speculative decoding is never enabled (falsified on this host). Every
//! start verifies the model's SHA-256 against the operator-approved value
//! and refuses on mismatch.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use vanian_sovereign::policy::egress::LoopbackEndpoint;
use vanian_sovereign::ports::{PortError, PortErrorKind};

use super::llama_scoped::ScopedLlama;

/// Health-poll interval and ceiling while a model loads.
const POLL: Duration = Duration::from_millis(50);
const LOAD_TIMEOUT: Duration = Duration::from_secs(600);

/// A serving profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub model: PathBuf,
    pub model_sha256: String,
    pub extra_args: Vec<String>,
    pub n_slots: usize,
    pub ctx_per_slot: usize,
    /// Keep the server between requests (false = load on demand, stop after use).
    pub resident: bool,
}

impl Profile {
    /// Memory profile: smallest resident footprint measured.
    pub fn memory(model_q4: &Path, sha: &str) -> Self {
        Self {
            name: "memory".into(),
            model: model_q4.into(),
            model_sha256: sha.into(),
            extra_args: vec!["--no-repack".into()],
            n_slots: 2,
            ctx_per_slot: 4096,
            resident: false,
        }
    }
    /// Balanced profile: repacked Q4, resident.
    pub fn balanced(model_q4: &Path, sha: &str) -> Self {
        Self {
            name: "balanced".into(),
            model: model_q4.into(),
            model_sha256: sha.into(),
            extra_args: vec![],
            n_slots: 2,
            ctx_per_slot: 4096,
            resident: true,
        }
    }
    /// Speed profile: Q8_0 (faster than Q4 on the measured CPU), resident.
    pub fn speed(model_q8: &Path, sha: &str) -> Self {
        Self {
            name: "speed".into(),
            model: model_q8.into(),
            model_sha256: sha.into(),
            extra_args: vec![],
            n_slots: 2,
            ctx_per_slot: 4096,
            resident: true,
        }
    }
}

fn perr(m: impl Into<String>) -> PortError {
    PortError::new(PortErrorKind::Inference, m)
}

/// Read buffer for streaming hashes (bounded memory regardless of file size).
const HASH_CHUNK: usize = 1 << 20;

/// SHA-256 of a file, streamed in [`HASH_CHUNK`] blocks.
///
/// Rationale: the earlier one-shot version read the whole model into memory
/// (measured: runtime RSS 6 → 838 MB while verifying a 1.1 GB model).
pub fn file_sha256(path: &Path) -> Result<String, PortError> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| perr(format!("{}: {e}", path.display())))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; HASH_CHUNK];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| perr(format!("{}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// A running, verified model server.
pub struct ModelServer {
    child: Child,
    pub client: ScopedLlama,
    pub load_ms: f64,
    pub verify_ms: f64,
    pub profile: Profile,
    slot_dir: PathBuf,
}

impl ModelServer {
    /// Verify the weights, start llama-server on `127.0.0.1:port`, wait for health.
    pub fn start(
        binary: &Path,
        profile: &Profile,
        port: u16,
        workdir: &Path,
    ) -> Result<Self, PortError> {
        let tv = Instant::now();
        let got = file_sha256(&profile.model)?;
        if got != profile.model_sha256 {
            return Err(PortError::new(
                PortErrorKind::ContractViolation,
                format!(
                    "model hash mismatch: expected {}, got {got}",
                    profile.model_sha256
                ),
            ));
        }
        let verify_ms = tv.elapsed().as_secs_f64() * 1000.0;
        // Slot erase requires --slot-save-path; the directory is private and
        // must stay empty (this client never saves KV state).
        let slot_dir = workdir.join(format!("slots-{port}"));
        std::fs::create_dir_all(&slot_dir).map_err(|e| perr(e.to_string()))?;
        set_mode_0700(&slot_dir)?;
        let log = std::fs::File::create(workdir.join(format!("llama-{port}.log")))
            .map_err(|e| perr(e.to_string()))?;
        let t0 = Instant::now();
        let mut cmd = Command::new(binary);
        cmd.arg("-m")
            .arg(&profile.model)
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--no-webui",
            ])
            .args([
                "-np",
                &profile.n_slots.to_string(),
                "-c",
                &(profile.n_slots * profile.ctx_per_slot).to_string(),
            ])
            .args([
                "-t",
                &std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
                    .to_string(),
            ])
            .arg("--slot-save-path")
            .arg(format!("{}/", slot_dir.display()))
            .args(&profile.extra_args)
            .stdout(Stdio::from(
                log.try_clone().map_err(|e| perr(e.to_string()))?,
            ))
            .stderr(Stdio::from(log));
        let mut child = cmd
            .spawn()
            .map_err(|e| perr(format!("llama-server spawn: {e}")))?;
        let ep = LoopbackEndpoint::parse(&format!("127.0.0.1:{port}"))
            .map_err(|e| perr(format!("{e:?}")))?;
        let client = ScopedLlama::new(
            ep,
            profile.n_slots,
            &profile.model_sha256,
            Duration::from_secs(600),
        )?;
        while !client.healthy() {
            if let Ok(Some(status)) = child.try_wait() {
                return Err(perr(format!("llama-server exited during load: {status}")));
            }
            if t0.elapsed() > LOAD_TIMEOUT {
                let _ = child.kill();
                return Err(perr("llama-server load timeout"));
            }
            std::thread::sleep(POLL);
        }
        Ok(Self {
            child,
            client,
            load_ms: t0.elapsed().as_secs_f64() * 1000.0,
            verify_ms,
            profile: profile.clone(),
            slot_dir,
        })
    }

    /// Server process id (for the meter).
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Stop the server and remove the slot directory. Errors if any slot
    /// file was written (it must never be).
    pub fn stop(mut self) -> Result<(), PortError> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let leftover = std::fs::read_dir(&self.slot_dir)
            .map(|d| d.count())
            .unwrap_or(0);
        let _ = std::fs::remove_dir_all(&self.slot_dir);
        if leftover > 0 {
            return Err(PortError::new(
                PortErrorKind::ContractViolation,
                format!("{leftover} KV slot file(s) were written"),
            ));
        }
        Ok(())
    }
}

impl Drop for ModelServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.slot_dir);
    }
}

fn set_mode_0700(p: &Path) -> Result<(), PortError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| perr(e.to_string()))
}

#[cfg(test)]
mod hash_tests {
    use super::*;

    #[test]
    fn streamed_hash_matches_one_shot_across_chunk_boundaries() {
        for len in [
            0usize,
            1,
            HASH_CHUNK - 1,
            HASH_CHUNK,
            HASH_CHUNK + 1,
            3 * HASH_CHUNK + 7,
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
            let f = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(f.path(), &data).unwrap();
            assert_eq!(
                file_sha256(f.path()).unwrap(),
                hex::encode(aip_crypto::sha256(&data)),
                "len {len}"
            );
        }
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(file_sha256(Path::new("/nonexistent/model.gguf")).is_err());
    }
}
