//! Which of the probe's sensors this host can open, through the probe's own
//! `SensorSet::open`, one sensor at a time.
//!
//! Prints one JSON object per sensor: `{"sensor", "open", "detail"}`, where
//! `detail` is the opener's own error when it fails. It opens and immediately
//! drops each sensor; it reads no events and claims nothing about coverage
//! beyond "the kernel let this sensor open here, now".
//!
//! Used by the enterprise WOW lab check (loop item 0.4). `fanotify` needs a
//! mount to mark: `/tmp` is used, which is enough to test that the queue opens.
//!
//!     cargo run --release -p aip-probe --example sensor_matrix

use aip_probe::config::SensorConfig;
use aip_probe::sensors::SensorSet;

fn one(name: &str) -> SensorConfig {
    let mut c = SensorConfig::default();
    match name {
        "sched" => c.sched = true,
        "cgroup" => c.cgroup = true,
        "sockstate" => c.sockstate = true,
        "socksend" => c.socksend = true,
        "connector" => c.connector = true,
        "fanotify" => {
            c.fanotify = true;
            c.fanotify_path = Some("/tmp".into());
        }
        "afpacket" => c.afpacket = true,
        _ => unreachable!("sensor list below is the closed set"),
    }
    c
}

fn main() {
    // The closed set from `SensorConfig::parse`.
    let sensors = [
        "sched",
        "cgroup",
        "sockstate",
        "socksend",
        "connector",
        "fanotify",
        "afpacket",
    ];
    let mut opened = 0;
    for name in sensors {
        let (open, detail) = match SensorSet::open("sensor-matrix", one(name)) {
            Ok(set) => {
                drop(set);
                (true, String::new())
            }
            Err(e) => (false, e),
        };
        opened += usize::from(open);
        println!(
            "{}",
            serde_json::json!({"sensor": name, "open": open, "detail": detail})
        );
    }
    eprintln!("{opened}/{} sensors opened", sensors.len());
}
