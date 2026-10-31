//! `/proc`-based resource meter (Linux). Kernel counters, not self-reports.

use std::sync::Mutex;

use crate::ports::{Meter, ResourceSnapshot};

/// Clock ticks per second used by `/proc/<pid>/stat` on Linux x86-64.
/// (`sysconf(_SC_CLK_TCK)` is 100 on every mainstream Linux build; read
/// from `getconf` would need libc, which this crate avoids.)
const CLK_TCK: f64 = 100.0;

/// Snapshot of one process; `None` if it has exited.
pub fn snapshot(pid: u32) -> Option<ResourceSnapshot> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let f: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    let cpu = (f.get(11)?.parse::<f64>().ok()? + f.get(12)?.parse::<f64>().ok()?) / CLK_TCK;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let kb = |k: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(k))
            .and_then(|v| v.split_whitespace().next())
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0)
            / 1024.0
    };
    Some(ResourceSnapshot {
        cpu_s: cpu,
        rss_mib: kb("VmRSS:"),
        hwm_mib: kb("VmHWM:"),
    })
}

/// Meter over named processes; the runtime itself is always included.
pub struct ProcMeter {
    pids: Mutex<Vec<(String, u32)>>,
}

impl Default for ProcMeter {
    fn default() -> Self {
        Self {
            pids: Mutex::new(vec![("runtime".into(), std::process::id())]),
        }
    }
}

impl ProcMeter {
    /// Track another component (replaces an existing entry with that name).
    pub fn track(&self, name: &str, pid: u32) {
        if let Ok(mut p) = self.pids.lock() {
            p.retain(|(n, _)| n != name);
            p.push((name.into(), pid));
        }
    }

    /// Stop tracking a component (e.g. an unloaded model server).
    pub fn untrack(&self, name: &str) {
        if let Ok(mut p) = self.pids.lock() {
            p.retain(|(n, _)| n != name);
        }
    }
}

impl Meter for ProcMeter {
    fn snapshot(&self) -> Vec<(String, ResourceSnapshot)> {
        let pids = self.pids.lock().map(|p| p.clone()).unwrap_or_default();
        pids.into_iter()
            .filter_map(|(n, pid)| snapshot(pid).map(|s| (n, s)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_own_process() {
        let s = snapshot(std::process::id()).unwrap();
        assert!(s.rss_mib > 0.0 && s.hwm_mib >= s.rss_mib && s.cpu_s >= 0.0);
        assert!(snapshot(u32::MAX).is_none());
    }
}
