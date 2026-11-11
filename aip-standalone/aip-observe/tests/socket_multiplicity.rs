#![cfg(target_os = "linux")]

//! Live /proc join cross-check against descriptors measured by fstat. This is
//! a second kernel interface on the same host, not independent administration.

use aip_observe::{ObservedEffect, ProcfsProbe};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;

fn inode(socket: &impl AsRawFd) -> u64 {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: a live borrowed descriptor and writable stat storage; the
    // output is read only after fstat reports successful initialization.
    assert_eq!(
        unsafe { libc::fstat(socket.as_raw_fd(), stat.as_mut_ptr()) },
        0
    );
    unsafe { stat.assume_init() }.st_ino
}

#[test]
fn stable_socket_multiplicity_matches_fstat_ground_truth() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let expected = [inode(&listener), inode(&client), inode(&server)];
    assert_ne!(expected[0], expected[1]);
    assert_ne!(expected[1], expected[2]);
    assert_ne!(expected[0], expected[2]);
    let probe = ProcfsProbe::new("p0-048-synthetic-socket-check");
    let mut samples = Vec::new();
    for _ in 0..40 {
        let (process, effects, malformed, repeated) =
            probe.observe_sockets_detailed(std::process::id()).unwrap();
        assert_eq!(process.process.pid, std::process::id());
        assert_eq!(malformed, 0, "the sampled table must parse for this check");
        let counts: Vec<usize> =
            expected
                .iter()
                .map(|wanted| {
                    effects.iter().filter(|effect| matches!(
                effect, ObservedEffect::SocketObserved { inode, .. } if inode == wanted
            )).count()
                })
                .collect();
        samples.push(serde_json::json!({
            "counts": counts, "repeated_rows": repeated,
            "malformed_rows": malformed, "process": process, "effects": effects,
        }));
    }
    let report = serde_json::json!({
        "scope": "Forty samples of three held loopback sockets; fstat ground truth",
        "independent_administration": false,
        "expected_inodes": expected, "samples": samples,
    });
    if let Ok(root) = std::env::var("P0_048_RETAIN_DIR") {
        let path = std::path::Path::new(&root).join("fstat-socket-samples.json");
        assert!(!path.exists(), "refuse to replace prior evidence");
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    for sample in &samples {
        assert_eq!(sample["counts"], serde_json::json!([1, 1, 1]), "{sample}");
    }
}
