use aip_crypto::custody::{Custodian, InMemoryCustodian};
use aip_install::{
    activate_staged_package_with_inventory, audit_persistent_installation,
    inspect_installation_recovery, stage_verified_package, upgrade_staged_package_with_inventory,
};
use aip_package::{build_package_v2, sign_package, verify_package_contents, PackageFile};
use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const ROOT: &str = "/mnt/aip-test/installations/aip-powerloss-run8";
const TRUSTED_KEY: &str = "/mnt/aip-test/recovery/aip-installer-run8.pub";
const INSTALLER_ID: &str = "aip-powerloss-lab-installer";
const PUBLISHER_ID: &str = "aip-powerloss-lab-publisher";
const AIBOM: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn make_verified_package(
    version: &str,
    publisher: &InMemoryCustodian,
    contents: &[u8],
) -> Result<aip_package::VerifiedPackage, Box<dyn Error>> {
    let package = build_package_v2(
        "aip-powerloss-agent",
        version,
        PUBLISHER_ID,
        AIBOM,
        vec![
            PackageFile {
                path: "bin/agent".into(),
                contents: contents.to_vec(),
            },
            PackageFile {
                path: "config/runtime.json".into(),
                contents: format!(r#"{{"version":"{version}","lab":true}}"#).into_bytes(),
            },
        ],
        vec!["bin/agent".into()],
    )?;

    let signature = sign_package(&package, publisher)?;
    let verified = verify_package_contents(&package, &signature, publisher.public_key(), AIBOM)?;

    Ok(verified)
}

fn persist_trusted_key(key: &[u8]) -> Result<(), Box<dyn Error>> {
    let path = Path::new(TRUSTED_KEY);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(key)?;
    file.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}

fn run_upgrade() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(ROOT);

    if root.exists() {
        return Err(format!(
            "Refusing to overwrite existing installation: {}",
            root.display()
        )
        .into());
    }

    fs::create_dir_all(&root)?;
    fs::create_dir_all("/mnt/aip-test/recovery")?;

    let installer = InMemoryCustodian::generate();
    let publisher = InMemoryCustodian::generate();

    // Persist the independent trust anchor before installation begins.
    persist_trusted_key(installer.public_key())?;

    println!("Creating initial package version 1.0.0...");
    let initial = make_verified_package(
        "1.0.0",
        &publisher,
        b"#!/bin/sh\necho AIP power-loss agent version 1.0.0\n",
    )?;

    let staged = stage_verified_package(&root, &initial)?;
    let activated = activate_staged_package_with_inventory(staged, INSTALLER_ID, &installer)?;

    println!(
        "Initial installation activated: {}",
        activated.release_name()
    );

    println!("Preparing upgrade package version 1.1.0...");
    let upgrade = make_verified_package(
        "1.1.0",
        &publisher,
        b"#!/bin/sh\necho AIP power-loss agent version 1.1.0\n",
    )?;

    let staged_upgrade = stage_verified_package(&root, &upgrade)?;

    // Checkpoint coordination uses /run (tmpfs), not the tested ext4 volume.
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").map_err(|_| "XDG_RUNTIME_DIR is not set")?;
    let marker_dir = Path::new(&runtime_dir).join("aip-powerloss-lab");
    fs::create_dir_all(&marker_dir)?;
    let marker = marker_dir.join("reached");
    let marker = marker
        .to_str()
        .ok_or("checkpoint marker path is not UTF-8")?;
    let _ = fs::remove_file(marker);

    std::env::set_var("AIP_POWERLOSS_MARKER", marker);
    std::env::set_var("AIP_POWERLOSS_STOP_AFTER", "SyncInstallationRoot");

    println!("Starting upgrade; waiting for SyncInstallationRoot checkpoint...");

    let _ = upgrade_staged_package_with_inventory(
        staged_upgrade,
        INSTALLER_ID,
        &installer,
        installer.public_key(),
    )?;

    Err("Checkpoint was not reached; upgrade unexpectedly returned".into())
}

fn recover() -> Result<(), Box<dyn Error>> {
    let trusted_key = fs::read(TRUSTED_KEY)?;
    let root = Path::new(ROOT);

    println!("=== Read-only recovery scan ===");
    let report = inspect_installation_recovery(root, &trusted_key)?;
    println!("{report:#?}");

    println!("=== Persistent installation audit ===");
    let _inventory = audit_persistent_installation(root, &trusted_key)?;
    println!("Current installation authenticated and audited successfully.");

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    match std::env::args().nth(1).as_deref() {
        Some("run") => run_upgrade(),
        Some("recover") => recover(),
        _ => Err("Usage: aip-powerloss-harness run|recover".into()),
    }
}
