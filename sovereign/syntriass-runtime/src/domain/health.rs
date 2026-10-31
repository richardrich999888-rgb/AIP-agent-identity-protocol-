//! Installation health and hardware checks. Pure: every function takes the
//! text of a `/proc` file (or a measured number) and returns a verdict, so
//! each rule is testable without the machine it describes.

use serde::Serialize;

/// Memory needed per byte of model file, measured: Qwen2.5-1.5B Q8_0
/// (1 894 532 128-byte file, 1807 MiB) peaked at 3690.4 MiB RSS
/// (research/capability-learning/results/sprint/baselines_bt/summary.json),
/// ratio 2.04, rounded up to 2.1. An estimate, not a guarantee.
pub const RSS_PER_MODEL_BYTE: f64 = 2.1;
/// Runtime + retrieval sidecar resident memory, measured ≈ 160 MiB; doubled for headroom.
pub const BASE_RSS_MIB: u64 = 320;

/// One check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

impl Check {
    pub fn new(name: &str, ok: bool, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok,
            detail: detail.into(),
        }
    }
}

/// Facts read from the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Hardware {
    pub cpus: usize,
    pub mem_total_mib: u64,
    pub mem_available_mib: u64,
    pub avx2: bool,
    pub avx512f: bool,
}

/// Parse `/proc/cpuinfo` + `/proc/meminfo` text.
pub fn hardware(cpuinfo: &str, meminfo: &str) -> Hardware {
    let cpus = cpuinfo
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count();
    let flags = cpuinfo
        .lines()
        .find(|l| l.starts_with("flags"))
        .unwrap_or("");
    let has = |f: &str| flags.split_whitespace().any(|x| x == f);
    let kib = |key: &str| -> u64 {
        meminfo
            .lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    Hardware {
        cpus,
        mem_total_mib: kib("MemTotal:") / 1024,
        mem_available_mib: kib("MemAvailable:") / 1024,
        avx2: has("avx2"),
        avx512f: has("avx512f"),
    }
}

/// Estimated peak memory (MiB) for serving a model file of `model_bytes`.
pub fn required_mib(model_bytes: u64) -> u64 {
    BASE_RSS_MIB + ((model_bytes as f64 * RSS_PER_MODEL_BYTE) / (1024.0 * 1024.0)).ceil() as u64
}

/// Does the host have enough memory now for a model of `model_bytes`?
pub fn memory_fits(hw: &Hardware, model_bytes: u64, what: &str) -> Check {
    let need = required_mib(model_bytes);
    Check::new(
        &format!("memory:{what}"),
        hw.mem_available_mib >= need,
        format!(
            "needs ≈{need} MiB, available {} MiB (estimate from measured peak RSS)",
            hw.mem_available_mib
        ),
    )
}

/// CPU requirements: llama.cpp builds here target AVX2 at minimum.
pub fn cpu_ok(hw: &Hardware) -> Check {
    Check::new(
        "cpu",
        hw.avx2 && hw.cpus >= 2,
        format!(
            "{} CPUs, avx2={}, avx512f={} (needs ≥2 CPUs with AVX2; GPU not used)",
            hw.cpus, hw.avx2, hw.avx512f
        ),
    )
}

/// Default routes in `/proc/net/route` (IPv4) and `/proc/net/ipv6_route`.
/// An air-gapped installation must have none. Reading the tables sends no
/// packet. Interfaces named `lo` are ignored.
pub fn default_routes(route_v4: &str, route_v6: &str) -> Vec<String> {
    let mut out = vec![];
    for l in route_v4.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        // Iface Destination Gateway Flags … Mask: destination 0 with mask 0 is a default route.
        if f.len() >= 8 && f[0] != "lo" && f[1] == "00000000" && f[7] == "00000000" {
            out.push(format!("ipv4 default via {}", f[0]));
        }
    }
    for l in route_v6.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        // dest(32 hex) dest_prefix … iface (last field)
        if f.len() >= 10 && f[0].chars().all(|c| c == '0') && f[1] == "00" && f[9] != "lo" {
            out.push(format!("ipv6 default via {}", f[9]));
        }
    }
    out
}

/// Offline check from the routing tables.
pub fn offline(route_v4: &str, route_v6: &str) -> Check {
    let r = default_routes(route_v4, route_v6);
    Check::new(
        "offline",
        r.is_empty(),
        if r.is_empty() {
            "no default route (routing tables read; no packet sent)".to_string()
        } else {
            format!("external route present: {}", r.join("; "))
        },
    )
}

/// State directory must not be readable or writable by group/other.
pub fn private_mode(mode: u32, what: &str) -> Check {
    Check::new(
        &format!("permissions:{what}"),
        mode & 0o077 == 0,
        format!("mode {:o}", mode & 0o777),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const CPU: &str = "processor\t: 0\nflags\t\t: fpu sse avx2 avx512f\nprocessor\t: 1\nflags\t\t: fpu sse avx2 avx512f\n";
    const MEM: &str =
        "MemTotal:        8000000 kB\nMemFree:  100 kB\nMemAvailable:    4096000 kB\n";

    #[test]
    fn parses_hardware() {
        let h = hardware(CPU, MEM);
        assert_eq!((h.cpus, h.avx2, h.avx512f), (2, true, true));
        assert_eq!((h.mem_total_mib, h.mem_available_mib), (7812, 4000));
        assert!(cpu_ok(&h).ok);
        assert!(!cpu_ok(&hardware("processor\t: 0\nflags\t: sse\n", MEM)).ok);
    }

    #[test]
    fn memory_estimate_matches_the_measured_case_and_fails_closed() {
        // 1.5B Q8_0 file → measured 3690.4 MiB peak; the estimate must not be below it.
        let q8 = 1_894_532_128u64;
        assert!(required_mib(q8) >= 3691);
        let h = hardware(CPU, MEM);
        assert!(memory_fits(&h, 400_000_000, "q4").ok);
        assert!(
            !memory_fits(&h, q8, "q8").ok,
            "4000 MiB available is not enough for the 1.5B Q8 peak"
        );
        assert!(
            !memory_fits(&hardware(CPU, ""), 1, "x").ok,
            "unreadable meminfo fails closed"
        );
    }

    #[test]
    fn default_routes_detected_loopback_ignored() {
        let v4 = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
                  eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\n\
                  eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n";
        assert_eq!(default_routes(v4, ""), vec!["ipv4 default via eth0"]);
        assert!(!offline(v4, "").ok);
        let local = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n";
        assert!(offline(local, "").ok);
        let v6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n\
                  00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000002 00000000 80200001 lo\n";
        assert_eq!(default_routes("", v6), vec!["ipv6 default via eth0"]);
    }

    #[test]
    fn private_mode_rejects_group_or_world_access() {
        assert!(private_mode(0o40700, "state").ok);
        assert!(!private_mode(0o40750, "state").ok);
        assert!(!private_mode(0o100644, "key").ok);
    }
}
