use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use aip_aibom::seal::{verify_seal, Seal};
use aip_crypto::custody::{Custodian, InMemoryCustodian};
use aip_package::{
    build_package, export_package, package_from_export, sign_package, verify_package_contents,
    PackageFile, PortablePackageExport, PublisherTrustAnchor, MAX_ARCHIVE_BYTES,
};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

const MAX_EXPORT_JSON_BYTES: u64 = (MAX_ARCHIVE_BYTES as u64 * 4 / 3) + 4 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "aip-package",
    about = "Offline AIP package publishing and verification"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Build and sign a software-only demonstration package with an ephemeral
    /// in-memory custodian, then emit its public anchor separately.
    DemoPublish {
        #[arg(long)]
        input_dir: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        publisher_id: String,
        #[arg(long)]
        aibom_digest: String,
        #[arg(long)]
        export: PathBuf,
        #[arg(long)]
        anchors: PathBuf,
    },
    /// Verify an export offline and extract only verified payload files.
    Verify {
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        anchors: PathBuf,
        #[arg(long)]
        aibom_digest: Option<String>,
        #[arg(long, requires_all = ["aibom_seal", "aibom_anchor"], conflicts_with = "aibom_digest")]
        aibom_manifest: Option<PathBuf>,
        #[arg(long, requires_all = ["aibom_manifest", "aibom_anchor"], conflicts_with = "aibom_digest")]
        aibom_seal: Option<PathBuf>,
        #[arg(long, requires_all = ["aibom_manifest", "aibom_seal"], conflicts_with = "aibom_digest")]
        aibom_anchor: Option<PathBuf>,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        accepted_name: Option<String>,
        #[arg(long)]
        accepted_publisher: Option<String>,
        /// Minimum strict numeric version: exactly MAJOR.MINOR.PATCH, no
        /// pre-release/build suffix and no zero-padded components.
        #[arg(long)]
        minimum_version: Option<String>,
        #[arg(long = "revoked-publisher")]
        revoked_publishers: Vec<String>,
        /// Revoked release in `publisher/name@MAJOR.MINOR.PATCH` form.
        #[arg(long = "revoked-release")]
        revoked_releases: Vec<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustFile {
    version: u16,
    publishers: Vec<PublisherTrustAnchor>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AibomAnchorFile {
    publisher_id: String,
    public_key_hex: String,
}

#[derive(Debug, Serialize)]
struct Report {
    status: &'static str,
    package_name: String,
    package_version: String,
    publisher_id: String,
    package_format_version: u16,
    archive_sha256: String,
    signature_verified: bool,
    inventory_verified: bool,
    aibom_digest_matched: bool,
    aibom_seal_verified: bool,
    policy_accepted: bool,
    extracted_files: Vec<String>,
    limitations: Vec<&'static str>,
}

fn read_limited(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|e| format!("cannot stat {label}: {e}"))?;
    if metadata.len() > limit {
        return Err(format!("{label} exceeds maximum size of {limit} bytes"));
    }
    let file = fs::File::open(path).map_err(|e| format!("cannot open {label}: {e}"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {label}: {e}"))?;
    if bytes.len() as u64 > limit {
        return Err(format!("{label} exceeds maximum size of {limit} bytes"));
    }
    Ok(bytes)
}

fn read_export(path: &Path) -> Result<PortablePackageExport, String> {
    let bytes = read_limited(path, MAX_EXPORT_JSON_BYTES, "package export")?;
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid package export schema: {e}"))
}

fn read_trust(path: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let bytes = read_limited(path, 1024 * 1024, "publisher anchors")?;
    let file: TrustFile = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid publisher anchor file: {e}"))?;
    if file.version != 1 || file.publishers.is_empty() {
        return Err("unsupported or empty publisher anchor file".into());
    }
    let mut anchors = BTreeMap::new();
    for PublisherTrustAnchor {
        publisher_id,
        public_key_hex,
    } in file.publishers
    {
        let key = hex::decode(&public_key_hex)
            .map_err(|e| format!("invalid public key for {publisher_id}: {e}"))?;
        if key.len() != 32 || publisher_id.trim().is_empty() {
            return Err(format!("invalid public anchor for {publisher_id}"));
        }
        if anchors.insert(publisher_id.clone(), key).is_some() {
            return Err(format!("duplicate publisher anchor: {publisher_id}"));
        }
    }
    Ok(anchors)
}

fn resolve_aibom_digest(
    digest: Option<String>,
    manifest_path: Option<PathBuf>,
    seal_path: Option<PathBuf>,
    anchor_path: Option<PathBuf>,
) -> Result<(String, bool), String> {
    if let Some(digest) = digest {
        if manifest_path.is_some() || seal_path.is_some() || anchor_path.is_some() {
            return Err(
                "provide either --aibom-digest or a manifest, seal and AIBOM anchor".into(),
            );
        }
        return Ok((digest, false));
    }
    let (Some(manifest_path), Some(seal_path), Some(anchor_path)) =
        (manifest_path, seal_path, anchor_path)
    else {
        return Err(
            "provide --aibom-digest or all of --aibom-manifest, --aibom-seal and --aibom-anchor"
                .into(),
        );
    };
    let manifest_bytes = read_limited(&manifest_path, 4 * 1024 * 1024, "AIBOM manifest")?;
    let manifest = aip_aibom::Manifest::from_json(&manifest_bytes)
        .map_err(|e| format!("invalid AIBOM manifest: {e}"))?;
    let seal_bytes = read_limited(&seal_path, 1024 * 1024, "AIBOM seal")?;
    let seal: Seal =
        serde_json::from_slice(&seal_bytes).map_err(|e| format!("invalid AIBOM seal: {e}"))?;
    let anchor_bytes = read_limited(&anchor_path, 1024 * 1024, "AIBOM publisher anchor")?;
    let anchor: AibomAnchorFile = serde_json::from_slice(&anchor_bytes)
        .map_err(|e| format!("invalid AIBOM publisher anchor: {e}"))?;
    if anchor.publisher_id != seal.publisher_id {
        return Err("AIBOM seal publisher does not match external AIBOM anchor".into());
    }
    let key = hex::decode(&anchor.public_key_hex)
        .map_err(|e| format!("invalid AIBOM public key: {e}"))?;
    if key.len() != 32 {
        return Err("AIBOM public key must contain 32 bytes".into());
    }
    let mut publishers = BTreeMap::new();
    publishers.insert(anchor.publisher_id, key);
    verify_seal(&seal, &manifest, &publishers)
        .map_err(|e| format!("AIBOM seal verification failed: {e}"))?;
    Ok((aip_aibom::canonical::manifest_digest_hex(&manifest), true))
}

fn strict_version(value: &str) -> Result<[u64; 3], String> {
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() != 3 {
        return Err(format!("version {value:?} must be MAJOR.MINOR.PATCH"));
    }
    let mut out = [0; 3];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty()
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(format!("version {value:?} is not a strict numeric version"));
        }
        out[i] = part
            .parse()
            .map_err(|_| format!("version component overflows in {value:?}"))?;
    }
    Ok(out)
}

fn check_policy(
    name: &str,
    version: &str,
    publisher: &str,
    accepted_name: Option<&str>,
    accepted_publisher: Option<&str>,
    minimum_version: Option<&str>,
    revoked_publishers: &[String],
    revoked_releases: &[String],
) -> Result<(), String> {
    if accepted_name.is_some_and(|accepted| accepted != name) {
        return Err("package name is not accepted by verifier policy".into());
    }
    if accepted_publisher.is_some_and(|accepted| accepted != publisher) {
        return Err("publisher is not accepted by verifier policy".into());
    }
    if revoked_publishers
        .iter()
        .any(|revoked| revoked == publisher)
    {
        return Err("publisher is revoked by verifier policy".into());
    }
    let release_key = format!("{publisher}/{name}@{version}");
    if revoked_releases
        .iter()
        .any(|revoked| revoked == &release_key)
    {
        return Err("package release is revoked by verifier policy".into());
    }
    if let Some(minimum) = minimum_version {
        if strict_version(version)? < strict_version(minimum)? {
            return Err("package release is below verifier minimum version".into());
        }
    }
    Ok(())
}

fn write_verified_payload(
    output_dir: &Path,
    files: &[aip_package::VerifiedPackageFile],
) -> Result<(), String> {
    fs::create_dir(output_dir).map_err(|e| format!("cannot create extraction directory: {e}"))?;
    let mut created_files = Vec::new();
    let result = (|| -> Result<(), String> {
        for file in files {
            let relative = Path::new(file.path());
            let parent = relative.parent().unwrap_or_else(|| Path::new(""));
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(output_dir.join(parent))
                    .map_err(|e| format!("cannot create payload directory: {e}"))?;
            }
            let path = output_dir.join(relative);
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|e| format!("cannot create verified payload {}: {e}", path.display()))?;
            created_files.push(path);
            output
                .write_all(file.contents())
                .map_err(|e| format!("cannot write verified payload: {e}"))?;
            output
                .sync_all()
                .map_err(|e| format!("cannot sync verified payload: {e}"))?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        for path in created_files {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_dir_all(output_dir);
        return Err(error);
    }
    Ok(())
}

fn collect_files(root: &Path, current: &Path, files: &mut Vec<PackageFile>) -> Result<(), String> {
    let mut entries = fs::read_dir(current)
        .map_err(|e| format!("cannot read input directory {}: {e}", current.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("cannot enumerate input directory: {e}"))?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|e| format!("cannot inspect input: {e}"))?;
        if kind.is_symlink() {
            return Err(format!(
                "input symlinks are not accepted: {}",
                path.display()
            ));
        } else if kind.is_dir() {
            collect_files(root, &path, files)?;
        } else if kind.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or_else(|| "input paths must be UTF-8".to_string())?
                .replace('\\', "/");
            let contents =
                fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            files.push(PackageFile {
                path: rel,
                contents,
            });
        } else {
            return Err(format!("unsupported input file type: {}", path.display()));
        }
    }
    Ok(())
}

fn create_demo(
    input_dir: PathBuf,
    name: String,
    version: String,
    publisher_id: String,
    aibom_digest: String,
    export_path: PathBuf,
    anchors_path: PathBuf,
) -> Result<(), String> {
    let mut files = Vec::new();
    collect_files(&input_dir, &input_dir, &mut files)?;
    let package = build_package(&name, &version, &publisher_id, &aibom_digest, files)
        .map_err(|e| format!("package build failed: {e}"))?;
    let custodian = InMemoryCustodian::generate();
    let signature =
        sign_package(&package, &custodian).map_err(|e| format!("package signing failed: {e}"))?;
    let export =
        export_package(&package, &signature).map_err(|e| format!("package export failed: {e}"))?;
    let anchor = PublisherTrustAnchor {
        publisher_id,
        public_key_hex: hex::encode(custodian.public_key()),
    };
    let anchors = serde_json::json!({ "version": 1, "publishers": [anchor] });
    let export_bytes = serde_json::to_vec_pretty(&export).map_err(|e| e.to_string())?;
    let anchor_bytes = serde_json::to_vec_pretty(&anchors).map_err(|e| e.to_string())?;

    let mut first = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&export_path)
        .map_err(|e| format!("cannot create package export: {e}"))?;
    let first_result = first
        .write_all(&export_bytes)
        .and_then(|_| first.write_all(b"\n"));
    drop(first);
    if let Err(e) = first_result {
        let _ = fs::remove_file(&export_path);
        return Err(format!("cannot write package export: {e}"));
    }
    let mut second = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&anchors_path)
    {
        Ok(file) => file,
        Err(e) => {
            let _ = fs::remove_file(&export_path);
            return Err(format!("cannot create public anchors: {e}"));
        }
    };
    let second_result = second
        .write_all(&anchor_bytes)
        .and_then(|_| second.write_all(b"\n"));
    drop(second);
    if let Err(e) = second_result {
        let _ = fs::remove_file(&anchors_path);
        let _ = fs::remove_file(&export_path);
        return Err(format!("cannot write public anchors: {e}"));
    }
    println!("Created signed package export: {}", export_path.display());
    println!("Created public anchor file: {}", anchors_path.display());
    eprintln!("Demo key was ephemeral and is not retained. Authenticate the anchor through a separate trusted channel.");
    Ok(())
}

fn verify(
    package_path: PathBuf,
    anchors_path: PathBuf,
    aibom_digest: Option<String>,
    aibom_manifest: Option<PathBuf>,
    aibom_seal: Option<PathBuf>,
    aibom_anchor: Option<PathBuf>,
    output_dir: PathBuf,
    accepted_name: Option<String>,
    accepted_publisher: Option<String>,
    minimum_version: Option<String>,
    revoked_publishers: Vec<String>,
    revoked_releases: Vec<String>,
) -> Result<(), String> {
    let (aibom_digest, aibom_seal_verified) =
        resolve_aibom_digest(aibom_digest, aibom_manifest, aibom_seal, aibom_anchor)?;
    let export = read_export(&package_path)?;
    let anchors = read_trust(&anchors_path)?;
    let publisher_id = export.publisher_id.clone();
    let public_key = anchors
        .get(&publisher_id)
        .ok_or_else(|| format!("publisher {publisher_id:?} has no external trust anchor"))?;
    let (package, signature) =
        package_from_export(export).map_err(|e| format!("invalid package export: {e}"))?;
    let verified = verify_package_contents(&package, &signature, public_key, &aibom_digest)
        .map_err(|e| format!("package verification failed: {e}"))?;
    check_policy(
        &verified.manifest().name,
        &verified.manifest().version,
        &verified.manifest().publisher_id,
        accepted_name.as_deref(),
        accepted_publisher.as_deref(),
        minimum_version.as_deref(),
        &revoked_publishers,
        &revoked_releases,
    )?;
    let extracted_files = verified
        .files()
        .iter()
        .map(|file| file.path().to_string())
        .collect::<Vec<_>>();
    write_verified_payload(&output_dir, verified.files())?;
    let report = Report {
        status: "VERIFIED",
        package_name: verified.manifest().name.clone(),
        package_version: verified.manifest().version.clone(),
        publisher_id: verified.manifest().publisher_id.clone(),
        package_format_version: verified.manifest().format_version,
        archive_sha256: hex::encode(verified.archive_sha256()),
        signature_verified: true,
        inventory_verified: true,
        aibom_digest_matched: true,
        aibom_seal_verified,
        policy_accepted: true,
        extracted_files,
        limitations: vec![
            "A valid signature does not prove that package contents are safe.",
            "Package verification does not authorize installation or execution.",
            "AIBOM authenticity is established only when an AIBOM manifest and detached seal are verified against a separate AIBOM publisher anchor.",
        ],
    };
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    Ok(())
}

fn run() -> Result<(), String> {
    match Cli::parse().command {
        Command::DemoPublish {
            input_dir,
            name,
            version,
            publisher_id,
            aibom_digest,
            export,
            anchors,
        } => create_demo(
            input_dir,
            name,
            version,
            publisher_id,
            aibom_digest,
            export,
            anchors,
        ),
        Command::Verify {
            package,
            anchors,
            aibom_digest,
            aibom_manifest,
            aibom_seal,
            aibom_anchor,
            output_dir,
            accepted_name,
            accepted_publisher,
            minimum_version,
            revoked_publishers,
            revoked_releases,
        } => verify(
            package,
            anchors,
            aibom_digest,
            aibom_manifest,
            aibom_seal,
            aibom_anchor,
            output_dir,
            accepted_name,
            accepted_publisher,
            minimum_version,
            revoked_publishers,
            revoked_releases,
        ),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("aip-package: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn strict_numeric_versions_compare_componentwise() {
        assert!(strict_version("1.10.0").unwrap() > strict_version("1.9.9").unwrap());
        assert!(strict_version("01.2.3").is_err());
        assert!(strict_version("1.2.3-rc1").is_err());
        assert!(strict_version("1.2").is_err());
    }

    #[test]
    fn policy_rejects_below_minimum_and_revoked_release() {
        assert!(check_policy(
            "engine",
            "1.2.0",
            "pub",
            None,
            None,
            Some("1.3.0"),
            &[],
            &[]
        )
        .is_err());
        assert!(check_policy(
            "engine",
            "1.3.0",
            "pub",
            None,
            None,
            None,
            &[],
            &["pub/engine@1.3.0".into()]
        )
        .is_err());
    }
}

#[cfg(test)]
mod aibom_tests {
    use super::*;
    use aip_aibom::model::*;

    fn fixture_manifest() -> aip_aibom::Manifest {
        aip_aibom::Manifest {
            schema_version: aip_aibom::model::AIBOM_SCHEMA_VERSION,
            validity: Validity {
                issued_at_ms: 1,
                valid_until_ms: Some(10_000),
            },
            agent: AgentIdentity {
                id: "agent-test".into(),
                name: "Test Agent".into(),
                owner: "team".into(),
                version: "1.0.0".into(),
                deployment: "offline-test".into(),
            },
            models: vec![],
            frameworks: vec![],
            tools: vec![],
            permissions: Permissions::default(),
            data_access: vec![],
            environment: Environment {
                runtime: RuntimeKind::Container,
                network: NetworkPosture::Restricted,
                binary: None,
            },
            relationships: Relationships::default(),
            security_controls: vec![],
            crypto: CryptoPosture::default(),
            supply_chain: vec![],
            governance: Governance::default(),
        }
    }

    #[test]
    fn accepts_independently_sealed_aibom_and_derives_canonical_digest() {
        let dir = std::env::temp_dir().join(format!("aip-aibom-cli-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let manifest = fixture_manifest();
        let keys = aip_crypto::generate_ed25519_keypair();
        let publisher =
            aip_aibom::seal::Publisher::new("aibom-publisher", &keys.private_key, &keys.public_key)
                .unwrap();
        let seal = publisher.seal(&manifest, 100).unwrap();
        let manifest_path = dir.join("manifest.json");
        let seal_path = dir.join("seal.json");
        let anchor_path = dir.join("anchor.json");
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::write(&seal_path, serde_json::to_vec(&seal).unwrap()).unwrap();
        fs::write(
            &anchor_path,
            serde_json::to_vec(&AibomAnchorFile {
                publisher_id: "aibom-publisher".into(),
                public_key_hex: hex::encode(&keys.public_key),
            })
            .unwrap(),
        )
        .unwrap();
        let (digest, sealed) = resolve_aibom_digest(
            None,
            Some(manifest_path.clone()),
            Some(seal_path.clone()),
            Some(anchor_path.clone()),
        )
        .unwrap();
        assert!(sealed);
        assert_eq!(digest, aip_aibom::canonical::manifest_digest_hex(&manifest));

        fs::write(
            &anchor_path,
            serde_json::to_vec(&AibomAnchorFile {
                publisher_id: "aibom-publisher".into(),
                public_key_hex: hex::encode(aip_crypto::generate_ed25519_keypair().public_key),
            })
            .unwrap(),
        )
        .unwrap();
        assert!(resolve_aibom_digest(
            None,
            Some(manifest_path),
            Some(seal_path),
            Some(anchor_path)
        )
        .is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
