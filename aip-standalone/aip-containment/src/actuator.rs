//! Actuation: the one seam between a decision and the kernel.
//!
//! The trait takes an [`Attributed`] target and a [`ContainmentAction`];
//! it cannot be reached with a pid, a finding, a strength or a string. The
//! only production implementation is [`CgroupV2Freezer`]: it creates a
//! cgroup for the instance, moves it there, writes `1` to `cgroup.freeze`
//! and reports `Applied` only once the kernel's `cgroup.events` says
//! `frozen 1`. Every failure along the way reverts what was done and fails
//! open (Skill 9 §12).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use aip_types::ProcessInstance;
use serde::{Deserialize, Serialize};

use crate::attribution::Attributed;
use crate::record::ContainmentAction;

/// How an action was, or would be, applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mechanism {
    /// Linux cgroup v2 `cgroup.freeze` on a cgroup created for the target.
    CgroupV2Freeze,
    /// A test double that recorded the call and touched nothing. Named so
    /// a record can never pass one off as an effect.
    TestDouble,
}

impl Mechanism {
    pub fn code(self) -> u8 {
        match self {
            Mechanism::CgroupV2Freeze => 0x01,
            Mechanism::TestDouble => 0x02,
        }
    }
}

/// An effect the actuator confirmed. `handle` identifies it for release
/// (the cgroup path for the freezer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    pub mechanism: Mechanism,
    pub handle: String,
}

/// Why actuation did not happen. Never evidence about the workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActuationFailure {
    /// The actuator cannot perform this action on this host.
    Unsupported { reason: String },
    /// A step failed; everything before it was reverted.
    Stage { stage: String, reason: String },
    /// The instance exited before the effect could be confirmed.
    TargetGone,
    /// The cgroup the actuator would use already exists, or holds a
    /// process other than the target. Nothing was frozen.
    WrongCgroup { reason: String },
}

impl ActuationFailure {
    pub fn code(&self) -> u8 {
        match self {
            ActuationFailure::Unsupported { .. } => 0x01,
            ActuationFailure::Stage { .. } => 0x02,
            ActuationFailure::TargetGone => 0x03,
            ActuationFailure::WrongCgroup { .. } => 0x04,
        }
    }
}

impl std::fmt::Display for ActuationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// The actuation seam.
pub trait Actuator {
    fn mechanism(&self) -> Mechanism;
    /// Apply `action` to the attributed instance. `Ok` only when the effect
    /// is confirmed.
    fn apply(
        &mut self,
        target: &Attributed,
        action: ContainmentAction,
    ) -> Result<Applied, ActuationFailure>;
    /// Undo a confirmed effect.
    fn release(&mut self, applied: &Applied) -> Result<(), ActuationFailure>;
}

// ─── cgroup v2 ───

/// Freezes one process instance in a cgroup of its own under a cgroup v2
/// hierarchy.
#[derive(Debug)]
pub struct CgroupV2Freezer {
    root: PathBuf,
    /// cgroup path → the cgroup the target came from, for release.
    origins: HashMap<String, String>,
}

impl CgroupV2Freezer {
    /// Find the cgroup v2 mount in `/proc/self/mountinfo`.
    pub fn detect() -> Result<Self, String> {
        let info = std::fs::read_to_string("/proc/self/mountinfo")
            .map_err(|e| format!("read mountinfo: {e}"))?;
        for line in info.lines() {
            let Some((pre, post)) = line.split_once(" - ") else {
                continue;
            };
            let fstype = post.split_whitespace().next().unwrap_or("");
            if fstype != "cgroup2" {
                continue;
            }
            let Some(mount) = pre.split_whitespace().nth(4) else {
                continue;
            };
            let root = PathBuf::from(mount);
            if root.join("cgroup.controllers").exists() && root.join("cgroup.procs").exists() {
                return Ok(Self::at(&root));
            }
        }
        Err("no cgroup2 mount with cgroup.controllers found".into())
    }

    /// Use `root` as the hierarchy. Nothing is checked until `apply`.
    pub fn at(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            origins: HashMap::new(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The cgroup this actuator uses for one instance: deterministic, so a
    /// repeated decision meets its own earlier cgroup rather than making a
    /// second.
    pub fn cgroup_path_for(&self, p: &ProcessInstance) -> PathBuf {
        self.root.join(format!(
            "ghost-contain-{}-{}",
            p.pid, p.pid_start_time_ticks
        ))
    }

    fn origin_of(pid: u32) -> Result<String, ActuationFailure> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(|e| {
            ActuationFailure::Stage {
                stage: "origin".into(),
                reason: e.to_string(),
            }
        })?;
        text.lines()
            .find_map(|l| l.strip_prefix("0::"))
            .map(|s| s.trim().to_string())
            .ok_or_else(|| ActuationFailure::Stage {
                stage: "origin".into(),
                reason: "no cgroup2 membership line in /proc/<pid>/cgroup".into(),
            })
    }

    fn procs_in(dir: &Path) -> Result<Vec<u32>, ActuationFailure> {
        let text = std::fs::read_to_string(dir.join("cgroup.procs")).map_err(|e| {
            ActuationFailure::Stage {
                stage: "read-procs".into(),
                reason: e.to_string(),
            }
        })?;
        Ok(text
            .lines()
            .filter_map(|l| l.trim().parse::<u32>().ok())
            .collect())
    }

    fn move_pid(dir: &Path, pid: u32) -> std::io::Result<()> {
        std::fs::write(dir.join("cgroup.procs"), pid.to_string())
    }

    fn events(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("cgroup.events")).unwrap_or_default()
    }

    fn is_frozen(dir: &Path) -> bool {
        Self::events(dir).lines().any(|l| l.trim() == "frozen 1")
    }

    /// Best-effort revert: thaw, move every member back to `origin`, remove
    /// the cgroup. Used on every failure path after creation.
    fn revert(&self, dir: &Path, origin: Option<&str>) {
        let _ = std::fs::write(dir.join("cgroup.freeze"), "0");
        let back = origin
            .map(|o| self.root.join(o.trim_start_matches('/')))
            .unwrap_or_else(|| self.root.clone());
        if let Ok(pids) = Self::procs_in(dir) {
            for pid in pids {
                if Self::move_pid(&back, pid).is_err() {
                    let _ = Self::move_pid(&self.root, pid);
                }
            }
        }
        for _ in 0..50 {
            if std::fs::remove_dir(dir).is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

impl Actuator for CgroupV2Freezer {
    fn mechanism(&self) -> Mechanism {
        Mechanism::CgroupV2Freeze
    }

    fn apply(
        &mut self,
        target: &Attributed,
        action: ContainmentAction,
    ) -> Result<Applied, ActuationFailure> {
        if action != ContainmentAction::FreezeProcess {
            return Err(ActuationFailure::Unsupported {
                reason: format!("{action:?} is not an effect this actuator produces"),
            });
        }
        if !self.root.join("cgroup.controllers").exists() {
            return Err(ActuationFailure::Stage {
                stage: "detect".into(),
                reason: format!("{} is not a cgroup v2 hierarchy", self.root.display()),
            });
        }
        let pid = target.process().pid;
        let dir = self.cgroup_path_for(target.process());
        if dir.exists() {
            return Err(ActuationFailure::WrongCgroup {
                reason: format!(
                    "{} already exists (members: {:?})",
                    dir.display(),
                    Self::procs_in(&dir).unwrap_or_default()
                ),
            });
        }
        if !target.is_alive() {
            return Err(ActuationFailure::TargetGone);
        }
        let origin = Self::origin_of(pid)?;
        std::fs::create_dir(&dir).map_err(|e| ActuationFailure::Stage {
            stage: "create".into(),
            reason: e.to_string(),
        })?;
        if !dir.join("cgroup.freeze").exists() {
            let _ = std::fs::remove_dir(&dir);
            return Err(ActuationFailure::Unsupported {
                reason: "cgroup.freeze is absent (kernel before 5.2, or not cgroup v2)".into(),
            });
        }
        if let Err(e) = Self::move_pid(&dir, pid) {
            let _ = std::fs::remove_dir(&dir);
            /// `ESRCH` from a `cgroup.procs` write means the process the
            /// number named is gone; nothing was moved.
            const ESRCH: i32 = 3;
            return Err(match e.raw_os_error() {
                Some(ESRCH) => ActuationFailure::TargetGone,
                _ => ActuationFailure::Stage {
                    stage: "attach".into(),
                    reason: e.to_string(),
                },
            });
        }
        // The target must actually be in the cgroup this actuator created.
        // Other members can only be processes the target itself forked
        // after the move — they inherit the cgroup, and freezing the cgroup
        // freezes them with it. That is the semantics of freezing a
        // process, and it is stated in CONTAINMENT_MODEL.md; a member that
        // is *not* the target and not its descendant cannot appear here,
        // because the cgroup did not exist a moment ago.
        match Self::procs_in(&dir) {
            Ok(members) if members.contains(&pid) => {}
            Ok(members) => {
                self.revert(&dir, Some(&origin));
                return Err(ActuationFailure::WrongCgroup {
                    reason: format!("members {members:?} do not include the target {pid}"),
                });
            }
            Err(e) => {
                self.revert(&dir, Some(&origin));
                return Err(e);
            }
        }
        if let Err(e) = std::fs::write(dir.join("cgroup.freeze"), "1") {
            self.revert(&dir, Some(&origin));
            return Err(ActuationFailure::Stage {
                stage: "freeze".into(),
                reason: e.to_string(),
            });
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1_000);
        while !Self::is_frozen(&dir) {
            if std::time::Instant::now() > deadline {
                self.revert(&dir, Some(&origin));
                return Err(ActuationFailure::Stage {
                    stage: "confirm".into(),
                    reason: format!(
                        "cgroup.events did not report frozen 1: {}",
                        Self::events(&dir)
                    ),
                });
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if !target.is_alive() {
            self.revert(&dir, Some(&origin));
            return Err(ActuationFailure::TargetGone);
        }
        let handle = dir.display().to_string();
        self.origins.insert(handle.clone(), origin);
        Ok(Applied {
            mechanism: Mechanism::CgroupV2Freeze,
            handle,
        })
    }

    fn release(&mut self, applied: &Applied) -> Result<(), ActuationFailure> {
        if applied.mechanism != Mechanism::CgroupV2Freeze {
            return Err(ActuationFailure::Unsupported {
                reason: format!("{:?} was not applied by this actuator", applied.mechanism),
            });
        }
        let dir = PathBuf::from(&applied.handle);
        if !dir.starts_with(&self.root) {
            return Err(ActuationFailure::WrongCgroup {
                reason: format!("{} is outside {}", dir.display(), self.root.display()),
            });
        }
        if !dir.exists() {
            return Err(ActuationFailure::Stage {
                stage: "release".into(),
                reason: format!("{} no longer exists", dir.display()),
            });
        }
        let origin = self.origins.remove(&applied.handle);
        self.revert(&dir, origin.as_deref());
        if dir.exists() {
            return Err(ActuationFailure::Stage {
                stage: "release".into(),
                reason: format!("{} could not be removed", dir.display()),
            });
        }
        Ok(())
    }
}
