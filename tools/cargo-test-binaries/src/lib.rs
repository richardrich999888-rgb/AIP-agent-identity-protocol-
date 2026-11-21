//! Locate real workspace executables for cross-package integration tests.
//! Cargo supplies CARGO_BIN_EXE only for binaries of the package under test.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

/// Build the requested (package, binary) pairs and return Cargo's actual paths.
/// A separate build directory, target triple, or coverage runner can change the
/// location of a test executable independently of the binaries it exercises.
pub fn build_binaries(
    manifest_dir: &str,
    targets: &[(&str, &str)],
) -> Result<BTreeMap<String, PathBuf>, String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command.current_dir(manifest_dir).args([
        "build",
        "--locked",
        "--message-format=json-render-diagnostics",
    ]);
    if !cfg!(debug_assertions) {
        command.arg("--release");
    }
    for &(package, binary) in targets {
        command.args(["--package", package, "--bin", binary]);
    }
    let output = command
        .output()
        .map_err(|err| format!("could not start Cargo for {targets:?}: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "Cargo build failed for {targets:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let mut paths = BTreeMap::new();
    for line in output
        .stdout
        .split(|&byte| byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let message: Value = serde_json::from_slice(line)
            .map_err(|err| format!("invalid Cargo artifact message: {err}"))?;
        if message["reason"] != "compiler-artifact" || message["target"]["kind"][0] != "bin" {
            continue;
        }
        if let (Some(name), Some(executable)) = (
            message["target"]["name"].as_str(),
            message["executable"].as_str(),
        ) {
            let path = PathBuf::from(executable);
            if targets.iter().any(|&(_, binary)| binary == name) && path.is_file() {
                paths.insert(name.to_owned(), path);
            }
        }
    }
    for &(package, binary) in targets {
        if !paths.contains_key(binary) {
            return Err(format!(
                "Cargo did not report an executable file for {package}/{binary}"
            ));
        }
    }
    Ok(paths)
}
