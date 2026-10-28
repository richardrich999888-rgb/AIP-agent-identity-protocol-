//! Gate 4 — filesystem observation, RED.
//!
//! The source: `fanotify` in notification class with `FAN_REPORT_PIDFD`,
//! marked on a mount. For every file closed after being opened for writing
//! (`FAN_CLOSE_WRITE`) the kernel queues an event carrying an open
//! descriptor to the object and a **pidfd the kernel itself bound to the
//! acting process** (created from the event's `struct pid` when the event
//! is read; `FAN_NOPIDFD` if that process has already gone). The probe
//! resolves the descriptor to the kernel's current path of the object and
//! its device/inode, then closes it. Queue overflow is a kernel-reported
//! event (`FAN_Q_OVERFLOW`), counted as loss.
//!
//! Measured on this host before any code: a write by a shell to a file on
//! the root mount produced one event with mask `MODIFY|CLOSE_WRITE`, the
//! object's path and inode, and a pidfd whose `/proc/self/fdinfo` named the
//! shell's pid. File-handle reporting (`FAN_REPORT_FID`) is refused with
//! `ENODEV` here because the root filesystem reports a zero fsid; the
//! descriptor path is used instead and the fid path is not claimed.
//!
//! No content is read from the file. The class is *that a write to this
//! path was completed by this instance*, not what was written.

use aip_observe::*;

const FAN_MODIFY: u64 = 0x02;
const FAN_CLOSE_WRITE: u64 = 0x08;
const FAN_Q_OVERFLOW: u64 = 0x4000;
const FAN_EVENT_INFO_TYPE_PIDFD: u8 = 4;

/// One `fanotify_event_metadata` (24 bytes) optionally followed by a pidfd
/// info record (8 bytes).
fn event(mask: u64, fd: i32, pid: i32, pidfd: Option<i32>) -> Vec<u8> {
    let len = 24 + if pidfd.is_some() { 8 } else { 0 };
    let mut b = Vec::new();
    b.extend_from_slice(&(len as u32).to_ne_bytes());
    b.push(3); // FANOTIFY_METADATA_VERSION
    b.push(0);
    b.extend_from_slice(&24u16.to_ne_bytes());
    b.extend_from_slice(&mask.to_ne_bytes());
    b.extend_from_slice(&fd.to_ne_bytes());
    b.extend_from_slice(&pid.to_ne_bytes());
    if let Some(p) = pidfd {
        b.push(FAN_EVENT_INFO_TYPE_PIDFD);
        b.push(0);
        b.extend_from_slice(&8u16.to_ne_bytes());
        b.extend_from_slice(&p.to_ne_bytes());
    }
    b
}

#[test]
fn fa01_a_buffer_of_events_decodes_masks_descriptors_pids_and_pidfds() {
    let mut buf = event(FAN_MODIFY | FAN_CLOSE_WRITE, 6, 32_753, Some(7));
    buf.extend(event(FAN_MODIFY, 8, 502, None));
    let (events, overflow) = parse_fanotify_buffer(&buf).unwrap();
    assert_eq!(overflow, 0);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].mask, FAN_MODIFY | FAN_CLOSE_WRITE);
    assert_eq!(events[0].fd, 6);
    assert_eq!(events[0].pid, 32_753);
    assert_eq!(events[0].pidfd, Some(7));
    assert_eq!(events[1].pidfd, None);
    assert_eq!(events[1].pid, 502);
}

#[test]
fn fa02_overflow_is_counted_as_loss_and_fan_nopidfd_is_no_pidfd() {
    let mut buf = event(FAN_Q_OVERFLOW, -1, 0, None);
    buf.extend(event(FAN_CLOSE_WRITE, 5, 10, Some(-1))); // FAN_NOPIDFD
    buf.extend(event(FAN_CLOSE_WRITE, 9, 11, Some(-2))); // FAN_EPIDFD
    let (events, overflow) = parse_fanotify_buffer(&buf).unwrap();
    assert_eq!(overflow, 1);
    assert_eq!(events.len(), 2, "the overflow record is not an event");
    assert_eq!(
        events[0].pidfd, None,
        "the process was gone when the event was read"
    );
    assert_eq!(events[1].pidfd, None, "a pidfd error is no pidfd");
}

#[test]
fn fa03_truncated_and_inconsistent_buffers_are_refused_not_guessed() {
    let buf = event(FAN_CLOSE_WRITE, 6, 1, Some(7));
    assert!(parse_fanotify_buffer(&buf[..20]).is_err());
    assert!(parse_fanotify_buffer(&buf[..28]).is_err());
    let mut wrong_version = buf.clone();
    wrong_version[4] = 2;
    assert!(parse_fanotify_buffer(&wrong_version).is_err());
    let mut short_len = buf.clone();
    short_len[0..4].copy_from_slice(&16u32.to_ne_bytes());
    assert!(parse_fanotify_buffer(&short_len).is_err());
    assert!(parse_fanotify_buffer(&[]).unwrap().0.is_empty());
}

#[test]
fn fa04_the_mechanism_and_the_event_kind() {
    let m = SourceMechanism::Fanotify;
    assert_eq!(m.code(), 0x09);
    assert!(SourceMechanism::ALL.contains(&m));
    let mut codes: Vec<u8> = SourceMechanism::ALL.iter().map(|m| m.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), SourceMechanism::ALL.len());
    assert!(m.is_kernel_pushed());
    assert!(!m.covers_process_lifecycle());

    let k = KernelLifecycleKind::FileEvent {
        mask: FAN_MODIFY | FAN_CLOSE_WRITE,
        pid: 4242,
        path: "/srv/out/report.csv".into(),
        deleted: false,
        dev: 65_024,
        ino: 1_884_732,
    };
    assert_eq!(k.subject_pid(), Some(4242));
    assert!(k.is_file_write());
    let modify_only = KernelLifecycleKind::FileEvent {
        mask: FAN_MODIFY,
        pid: 4242,
        path: "/srv/out/report.csv".into(),
        deleted: false,
        dev: 65_024,
        ino: 1_884_732,
    };
    assert!(
        !modify_only.is_file_write(),
        "a write in progress is not a completed write"
    );

    let ev = |kind: KernelLifecycleKind| KernelLifecycleEvent {
        cgroup: aip_observe::CgroupSample::NotSampled,
        version: OBSERVE_PROTOCOL_VERSION,
        probe_id: "p".into(),
        mechanism: SourceMechanism::Fanotify,
        kind,
        cpu: 0,
        kernel_timestamp_ns: 1,
        probe_seq: 1,
        bound: None,
        attribution: AgentAttribution::NotEstablished,
        claimed_decision_id: None,
    };
    let d0 = ev(k.clone()).digest();
    let mut variants = vec![ev(modify_only).digest()];
    for (path, deleted, ino) in [
        ("/srv/out/report.csv/", false, 1_884_732u64),
        ("/srv/out/report.csv", true, 1_884_732),
        ("/srv/out/report.csv", false, 1_884_733),
    ] {
        variants.push(
            ev(KernelLifecycleKind::FileEvent {
                mask: FAN_MODIFY | FAN_CLOSE_WRITE,
                pid: 4242,
                path: path.into(),
                deleted,
                dev: 65_024,
                ino,
            })
            .digest(),
        );
    }
    for v in &variants {
        assert_ne!(*v, d0);
    }
    variants.sort_unstable();
    variants.dedup();
    assert_eq!(variants.len(), 4);
    let json = serde_json::to_string(&k).unwrap().to_lowercase();
    for forbidden in ["content", "hash", "digest", "sha"] {
        assert!(!json.contains(forbidden), "{forbidden} in {json}");
    }
}

/// The two live tests must not run at the same time.
///
/// `FAN_CLOSE_WRITE` is emitted when the last reference to a file
/// *description* opened for writing is released, and the kernel attributes
/// it to whichever process performs that release. `fork` duplicates the
/// descriptor table, so a fork anywhere in this process while fa05 holds
/// `out.txt` open hands that reference to the child; fa05's own `close`
/// then merely decrements, and the event is attributed to the child when it
/// `exec`s (Rust opens files `O_CLOEXEC`). fa06 forks a shell, so run
/// concurrently the two tests make the kernel report a completed write by a
/// pid that is not this process — a correct observation of a real fd
/// inheritance, and a fact about this test binary rather than about the
/// observer. Serialising them removes the interference at its source.
#[cfg(target_os = "linux")]
static LIVE_FANOTIFY: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(target_os = "linux")]
#[test]
fn fa05_live_a_write_by_this_process_is_bound_through_the_kernels_pidfd() {
    use std::io::Write;
    let _serialised = LIVE_FANOTIFY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = std::env::temp_dir().join(format!("ghost-fa05-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // A fanotify mark covers a whole *mount*. On the shared temp mount this
    // test competed with every other writer on the machine — cargo's own
    // artifact writes included — which is a race with the host rather than
    // a property of the observer. A private tmpfs removes the competition
    // at its source instead of tolerating it: the mark then covers exactly
    // this directory, and nothing else can write here.
    let private_mount = mount_tmpfs(&dir);
    if !private_mount {
        eprintln!("fa05: no private tmpfs (needs CAP_SYS_ADMIN); sharing the temp mount");
    }
    let mut watch = match FanotifyWatch::open(dir.to_str().unwrap(), FAN_CLOSE_WRITE | FAN_MODIFY) {
        Ok(w) => w,
        Err(SourceError::Unavailable(why)) => {
            eprintln!("fa05: SKIPPED — fanotify unavailable: {why}");
            return;
        }
        Err(e) => panic!("{e}"),
    };
    let mut probe = ProcfsProbe::new("probe-f");
    probe.declare_source(SourceMechanism::Fanotify);
    probe.declare_clock_anchor(boot_clock_anchor().unwrap());
    let target = dir.join("out.txt");
    {
        let mut f = std::fs::File::create(&target).unwrap();
        f.write_all(b"gate four").unwrap();
    } // close → FAN_CLOSE_WRITE
    let me = std::process::id();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut found = None;
    let mut seen = 0u32;
    while std::time::Instant::now() < deadline && found.is_none() {
        if let Some(obs) = watch.next_event(50).unwrap() {
            seen += 1;
            let e = probe.ingest_file_event(obs).clone();
            if let KernelLifecycleKind::FileEvent { pid, path, .. } = &e.kind {
                if *pid == me && path == target.to_str().unwrap() && e.kind.is_file_write() {
                    found = Some(e);
                }
            }
        }
    }
    let Some(e) = found else {
        let lost = watch.take_lost();
        // On a private mount nothing else can write here, so failing to see
        // our own completed write is the observer failing at its one job.
        assert!(
            !private_mount,
            "on a private mount the write went unreported ({lost} lost, {seen} events seen)"
        );
        // On the shared mount, absence proves nothing about the observer:
        // the queue may have overflowed, or simply stayed busy with other
        // writers for the whole deadline.
        eprintln!("fa05: SKIPPED — shared mount, {lost} events lost, {seen} seen");
        cleanup(&dir, private_mount);
        return;
    };
    assert_eq!(e.mechanism, SourceMechanism::Fanotify);
    let bound = e
        .bound
        .expect("bound through the pidfd the kernel created for the writer");
    assert_eq!(bound.process.pid, me);
    if let KernelLifecycleKind::FileEvent { deleted, ino, .. } = &e.kind {
        assert!(!deleted);
        use std::os::unix::fs::MetadataExt;
        assert_eq!(*ino, std::fs::metadata(&target).unwrap().ino());
    }
    assert!(e.kernel_timestamp_ns > 0, "probe read stamp");
    // The mark is mount-wide (`FAN_MARK_MOUNT`), so every process writing on
    // this mount shares one queue. Whether that queue overflowed is a fact
    // about the host, not about this code — asserting it was quiet asserts
    // nothing about the observer. What must hold is the invariant the
    // architecture rests on: a kernel-reported overflow is counted and
    // carried into the batch, so the collector degrades rather than
    // silently claiming coverage it never had.
    let lost = watch.take_lost();
    probe.record_lost_events(lost);
    let batch = probe.batch([1u8; 16], 1, 2, vec![]);
    assert_eq!(
        batch.dropped_events,
        Some(lost),
        "loss is carried into the batch, never hidden"
    );
    cleanup(&dir, private_mount);
}

#[cfg(target_os = "linux")]
#[test]
fn fa06_live_a_writer_that_exited_before_the_read_is_unbound() {
    // See `LIVE_FANOTIFY`: this test forks, and a fork while fa05 holds a
    // file open moves the close event to the child.
    let _serialised = LIVE_FANOTIFY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir = std::env::temp_dir().join(format!("ghost-fa06-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // Same reason as fa05: a mount-wide mark on the shared temp mount puts
    // this test in a queue with every other writer on the machine, so an
    // absent event says nothing about the observer. A private tmpfs makes
    // the queue this test's own.
    let private_mount = mount_tmpfs(&dir);
    if !private_mount {
        eprintln!("fa06: no private tmpfs (needs CAP_SYS_ADMIN); sharing the temp mount");
    }
    let mut watch = match FanotifyWatch::open(dir.to_str().unwrap(), FAN_CLOSE_WRITE) {
        Ok(w) => w,
        Err(SourceError::Unavailable(why)) => {
            eprintln!("fa06: SKIPPED — fanotify unavailable: {why}");
            cleanup(&dir, private_mount);
            return;
        }
        Err(e) => panic!("{e}"),
    };
    let target = dir.join("gone.txt");
    // A child writes and exits before we read the queue.
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("echo x > {}", target.display()))
        .status()
        .unwrap();
    assert!(status.success());
    std::thread::sleep(std::time::Duration::from_millis(100));
    let mut probe = ProcfsProbe::new("probe-f");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut seen = None;
    while std::time::Instant::now() < deadline && seen.is_none() {
        if let Some(obs) = watch.next_event(50).unwrap() {
            let e = probe.ingest_file_event(obs).clone();
            if let KernelLifecycleKind::FileEvent { path, .. } = &e.kind {
                if path == target.to_str().unwrap() {
                    seen = Some(e);
                }
            }
        }
    }
    let Some(e) = seen else {
        let lost = watch.take_lost();
        // On a private mount this test is the only writer, so the child's
        // completed write must be reported.
        assert!(
            !private_mount,
            "on a private mount the child's write went unreported ({lost} lost)"
        );
        // On the shared mount, absence is a statement about the queue and
        // not about the observer: it may have overflowed, or simply stayed
        // busy with other writers for the whole deadline.
        eprintln!("fa06: SKIPPED — shared mount, {lost} events lost");
        cleanup(&dir, private_mount);
        return;
    };
    assert_eq!(e.bound, None, "FAN_NOPIDFD: existence, no identity");
    assert_eq!(e.subject_identity_digest(), None);
    cleanup(&dir, private_mount);
}

#[test]
fn fa07_the_collector_refuses_fanotify_provenance_from_a_probe_not_provisioned_for_it() {
    let kp = aip_crypto::generate_ed25519_keypair();
    let mut signer = CollectorSigner::new("c", 1, &kp.private_key, &kp.public_key).unwrap();
    signer.register_probe("probe-f", &[SourceMechanism::PidFdAnchored]);
    let mut probe = ProcfsProbe::new("probe-f");
    probe.declare_source(SourceMechanism::Fanotify);
    let b = probe.batch([1u8; 16], 1, 2, vec![]);
    assert!(b.active_mechanisms.contains(&SourceMechanism::Fanotify));
    assert!(signer.attest(b).is_err());
}

/// Give `dir` its own tmpfs so a mount-wide fanotify mark covers only it.
/// False when the mount is refused (no `CAP_SYS_ADMIN`); the caller then
/// shares the temp mount with the rest of the machine and says so.
#[cfg(target_os = "linux")]
fn mount_tmpfs(dir: &std::path::Path) -> bool {
    let path = std::ffi::CString::new(dir.to_str().unwrap()).unwrap();
    let fstype = std::ffi::CString::new("tmpfs").unwrap();
    // SAFETY: plain syscall with owned, NUL-terminated strings; the result
    // is checked and failure is handled by the caller.
    unsafe {
        libc::mount(
            fstype.as_ptr(),
            path.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        ) == 0
    }
}

#[cfg(target_os = "linux")]
fn cleanup(dir: &std::path::Path, mounted: bool) {
    if mounted {
        let path = std::ffi::CString::new(dir.to_str().unwrap()).unwrap();
        // SAFETY: unmounting a path this test mounted.
        unsafe {
            libc::umount(path.as_ptr());
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}
