//! Build-path regressions only; these tests claim no live observation.

use aip_edge::transport::{ensure_sibling_binaries, sibling_binary, SIBLING_BINARIES};

const RELOCATED: &str = "AIP_EDGE_SIBLING_TEST_RELOCATED";

// The actual sibling observer requires Linux's ProcfsProbe implementation.
#[cfg(target_os = "linux")]
#[test]
fn locates_fresh_siblings_from_a_relocated_test_executable() {
    let name = "locates_fresh_siblings_from_a_relocated_test_executable";
    if std::env::var(RELOCATED).as_deref() == Ok(name) {
        ensure_sibling_binaries().expect("build current sibling binaries");
        let own_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        for sibling in SIBLING_BINARIES {
            let path = sibling_binary(sibling).expect("locate Cargo's executable artifact");
            assert!(path.is_file(), "{} is missing", path.display());
            assert_ne!(path.parent(), Some(own_dir.as_path()));
        }
    } else {
        reexecute_relocated(name, false);
    }
}

#[test]
fn failed_fresh_build_cannot_reuse_adjacent_stale_binaries() {
    let name = "failed_fresh_build_cannot_reuse_adjacent_stale_binaries";
    if std::env::var(RELOCATED).as_deref() == Ok(name) {
        assert!(
            ensure_sibling_binaries().is_err(),
            "the unavailable Cargo must fail"
        );
        for sibling in SIBLING_BINARIES {
            assert!(
                sibling_binary(sibling).is_err(),
                "{sibling} reused a stale adjacent file"
            );
        }
    } else {
        reexecute_relocated(name, true);
    }
}

fn reexecute_relocated(test_name: &str, fail_build: bool) {
    // Reproduce coverage's nonstandard executable location without requiring
    // coverage tooling. Each child has a separate once-only build cache.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "aip-edge-sibling-path-{}-{nonce}",
        std::process::id()
    ));
    let directory = root.join("debug/build/aip-edge/coverage-hash/out");
    std::fs::create_dir_all(&directory).unwrap();
    let executable = directory.join(format!("sibling-test{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    let mut command = std::process::Command::new(&executable);
    command
        .args(["--exact", test_name, "--nocapture"])
        .env(RELOCATED, test_name);
    if fail_build {
        // These adjacent files would satisfy the old existence-only fallback.
        // The current attempted build must take precedence over all of them.
        for sibling in SIBLING_BINARIES {
            std::fs::copy(&executable, directory.join(sibling)).unwrap();
        }
        command.env("CARGO", directory.join("missing-cargo"));
    }
    let output = command.output().expect("run the relocated test executable");
    std::fs::remove_dir_all(root).unwrap();
    assert!(
        output.status.success(),
        "relocated sibling check failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
