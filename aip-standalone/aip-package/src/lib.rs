//! Signed AI package lifecycle for AIP.
//!
//! Package integrity, publisher authenticity, AIBOM inventory binding,
//! and execution authorization are separate security decisions.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Write};

use base64::Engine;
use serde::{Deserialize, Serialize};

pub const PACKAGE_FORMAT_VERSION: u16 = 1;
pub const PACKAGE_FORMAT_VERSION_V2: u16 = 2;
pub const PACKAGE_MANIFEST_FILE: &str = "aip-package.json";
const ARCHIVE_TIMESTAMP: zip::DateTime = zip::DateTime::DEFAULT;
const ARCHIVE_FILE_MODE: u32 = 0o644;
const DEFLATE_LEVEL: i64 = 6;

// Package verification resource limits (format v1).
pub const MAX_ARCHIVE_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_TOTAL_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_PACKAGE_ENTRIES: usize = 10_000;
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy)]
struct PackageLimits {
    max_archive_bytes: usize,
    max_file_bytes: u64,
    max_total_uncompressed_bytes: u64,
    max_package_entries: usize,
    max_manifest_bytes: u64,
}

struct PackageBuildOptions {
    executable_paths: BTreeSet<String>,
    format_version: u16,
}

impl PackageLimits {
    const PRODUCTION: Self = Self {
        max_archive_bytes: MAX_ARCHIVE_BYTES,
        max_file_bytes: MAX_FILE_BYTES,
        max_total_uncompressed_bytes: MAX_TOTAL_UNCOMPRESSED_BYTES,
        max_package_entries: MAX_PACKAGE_ENTRIES,
        max_manifest_bytes: MAX_MANIFEST_BYTES,
    };
}

#[derive(Debug)]
pub enum PackageError {
    InvalidMetadata(String),
    InvalidPath(String),
    DuplicatePath(String),
    ReservedPath(String),
    Serialization(String),
    Archive(String),
}

impl std::fmt::Display for PackageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMetadata(e) => write!(f, "invalid package metadata: {e}"),
            Self::InvalidPath(e) => write!(f, "invalid package path: {e}"),
            Self::DuplicatePath(e) => write!(f, "duplicate package path: {e}"),
            Self::ReservedPath(e) => write!(f, "reserved package path: {e}"),
            Self::Serialization(e) => write!(f, "package serialization error: {e}"),
            Self::Archive(e) => write!(f, "package archive error: {e}"),
        }
    }
}

impl std::error::Error for PackageError {}

#[derive(Debug, Clone)]
pub struct PackageFile {
    pub path: String,
    pub contents: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageFileEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    /// Present and true only for executable files in package format v2.
    #[serde(default, skip_serializing_if = "is_false")]
    pub executable: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageManifest {
    pub format_version: u16,
    pub name: String,
    pub version: String,
    pub publisher_id: String,
    pub aibom_manifest_sha256: String,
    pub files: Vec<PackageFileEntry>,
}

#[derive(Debug, Clone)]
pub struct BuiltPackage {
    pub manifest: PackageManifest,
    pub manifest_bytes: Vec<u8>,
    pub archive_bytes: Vec<u8>,
    pub archive_sha256: [u8; 32],
}

/// A package file whose bytes have passed publisher-authenticated
/// manifest inventory, size, permission, and SHA-256 verification.
#[derive(Debug, Clone)]
pub struct VerifiedPackageFile {
    path: String,
    contents: Vec<u8>,
    executable: bool,
}

impl VerifiedPackageFile {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    pub fn is_executable(&self) -> bool {
        self.executable
    }
}

/// A package that has passed complete publisher and payload verification.
///
/// Its fields are private: callers must obtain it through
/// `verify_package_contents()`.
#[derive(Debug, Clone)]
pub struct VerifiedPackage {
    manifest: PackageManifest,
    files: Vec<VerifiedPackageFile>,
    archive_sha256: [u8; 32],
    manifest_sha256: [u8; 32],
}

impl VerifiedPackage {
    pub fn manifest(&self) -> &PackageManifest {
        &self.manifest
    }

    pub fn files(&self) -> &[VerifiedPackageFile] {
        &self.files
    }

    /// SHA-256 of the exact archive bytes that passed verification.
    pub fn archive_sha256(&self) -> &[u8; 32] {
        &self.archive_sha256
    }

    /// SHA-256 of the exact embedded manifest bytes that passed verification.
    pub fn manifest_sha256(&self) -> &[u8; 32] {
        &self.manifest_sha256
    }
}

fn validate_label(value: &str, field: &str) -> Result<(), PackageError> {
    if value.trim().is_empty() {
        return Err(PackageError::InvalidMetadata(format!(
            "{field} must not be empty"
        )));
    }

    if value.len() > 256 || value.chars().any(char::is_control) {
        return Err(PackageError::InvalidMetadata(format!(
            "{field} has invalid length or control characters"
        )));
    }

    Ok(())
}

fn validate_digest(value: &str, field: &str) -> Result<(), PackageError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PackageError::InvalidMetadata(format!(
            "{field} must be a 32-byte SHA-256 hex digest"
        )));
    }

    Ok(())
}

fn validate_path(path: &str) -> Result<(), PackageError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains(':')
        || path.chars().any(char::is_control)
    {
        return Err(PackageError::InvalidPath(path.to_string()));
    }

    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(PackageError::InvalidPath(path.to_string()));
        }
    }

    if path == PACKAGE_MANIFEST_FILE {
        return Err(PackageError::ReservedPath(path.to_string()));
    }

    Ok(())
}

/// Build a deterministic ZIP package from in-memory file contents.
///
/// The AIBOM digest must come from a separately validated AIBOM manifest.
/// This function binds that digest into the package manifest; it does not
/// validate or seal the AIBOM itself.
pub fn build_package(
    name: &str,
    version: &str,
    publisher_id: &str,
    aibom_manifest_sha256: &str,
    files: Vec<PackageFile>,
) -> Result<BuiltPackage, PackageError> {
    build_package_with_options(
        name,
        version,
        publisher_id,
        aibom_manifest_sha256,
        files,
        PackageBuildOptions {
            executable_paths: BTreeSet::new(),
            format_version: PACKAGE_FORMAT_VERSION,
        },
        PackageLimits::PRODUCTION,
    )
}

/// Build a deterministic v2 package with explicit executable declarations.
///
/// Executable paths are part of the signed manifest and receive ZIP mode 0755.
/// All other payload files receive mode 0644. The input paths must refer to
/// files present in `files`.
pub fn build_package_v2(
    name: &str,
    version: &str,
    publisher_id: &str,
    aibom_manifest_sha256: &str,
    files: Vec<PackageFile>,
    executable_paths: Vec<String>,
) -> Result<BuiltPackage, PackageError> {
    let unique_executable_paths: BTreeSet<String> = executable_paths.iter().cloned().collect();

    if unique_executable_paths.len() != executable_paths.len() {
        return Err(PackageError::InvalidMetadata(
            "duplicate executable path declaration".into(),
        ));
    }

    build_package_with_options(
        name,
        version,
        publisher_id,
        aibom_manifest_sha256,
        files,
        PackageBuildOptions {
            executable_paths: unique_executable_paths,
            format_version: PACKAGE_FORMAT_VERSION_V2,
        },
        PackageLimits::PRODUCTION,
    )
}

#[cfg(test)]
fn build_package_with_limits(
    name: &str,
    version: &str,
    publisher_id: &str,
    aibom_manifest_sha256: &str,
    files: Vec<PackageFile>,
    limits: PackageLimits,
) -> Result<BuiltPackage, PackageError> {
    build_package_with_options(
        name,
        version,
        publisher_id,
        aibom_manifest_sha256,
        files,
        PackageBuildOptions {
            executable_paths: BTreeSet::new(),
            format_version: PACKAGE_FORMAT_VERSION,
        },
        limits,
    )
}

fn build_package_with_options(
    name: &str,
    version: &str,
    publisher_id: &str,
    aibom_manifest_sha256: &str,
    mut files: Vec<PackageFile>,
    options: PackageBuildOptions,
    limits: PackageLimits,
) -> Result<BuiltPackage, PackageError> {
    let executable_paths = options.executable_paths;
    let format_version = options.format_version;

    validate_label(name, "name")?;
    validate_label(version, "version")?;
    validate_label(publisher_id, "publisher_id")?;
    validate_digest(aibom_manifest_sha256, "aibom_manifest_sha256")?;

    if files.len() > limits.max_package_entries {
        return Err(PackageError::InvalidMetadata(
            "package contains too many files".into(),
        ));
    }

    let mut seen = BTreeSet::new();
    let mut total_uncompressed_bytes = 0u64;

    for path in &executable_paths {
        validate_path(path)?;
    }

    for file in &files {
        validate_path(&file.path)?;

        if !seen.insert(file.path.clone()) {
            return Err(PackageError::DuplicatePath(file.path.clone()));
        }

        let file_size = u64::try_from(file.contents.len())
            .map_err(|_| PackageError::InvalidMetadata("file size conversion overflow".into()))?;

        if file_size > limits.max_file_bytes {
            return Err(PackageError::InvalidMetadata(format!(
                "file exceeds maximum uncompressed size: {}",
                file.path
            )));
        }

        total_uncompressed_bytes =
            total_uncompressed_bytes
                .checked_add(file_size)
                .ok_or_else(|| {
                    PackageError::InvalidMetadata("total uncompressed size overflow".into())
                })?;

        if total_uncompressed_bytes > limits.max_total_uncompressed_bytes {
            return Err(PackageError::InvalidMetadata(
                "package exceeds maximum total uncompressed size".into(),
            ));
        }
    }

    if executable_paths.iter().any(|path| !seen.contains(path)) {
        return Err(PackageError::InvalidMetadata(
            "executable declaration references a file absent from the package".into(),
        ));
    }

    if format_version == PACKAGE_FORMAT_VERSION && !executable_paths.is_empty() {
        return Err(PackageError::InvalidMetadata(
            "v1 packages cannot declare executable files".into(),
        ));
    }

    files.sort_by(|a, b| a.path.cmp(&b.path));

    let entries: Vec<PackageFileEntry> = files
        .iter()
        .map(|file| PackageFileEntry {
            path: file.path.clone(),
            size: file.contents.len() as u64,
            sha256: hex::encode(aip_crypto::sha256(&file.contents)),
            executable: executable_paths.contains(&file.path),
        })
        .collect();

    let manifest = PackageManifest {
        format_version,
        name: name.to_string(),
        version: version.to_string(),
        publisher_id: publisher_id.to_string(),
        aibom_manifest_sha256: aibom_manifest_sha256.to_ascii_lowercase(),
        files: entries,
    };

    // Struct field order and sorted file entries make this serialization stable.
    let manifest_bytes =
        serde_json::to_vec(&manifest).map_err(|e| PackageError::Serialization(e.to_string()))?;

    if manifest_bytes.len() as u64 > limits.max_manifest_bytes {
        return Err(PackageError::InvalidMetadata(
            "package manifest exceeds maximum size".into(),
        ));
    }

    let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .compression_level(Some(DEFLATE_LEVEL))
        .last_modified_time(ARCHIVE_TIMESTAMP)
        .unix_permissions(ARCHIVE_FILE_MODE);

    let mut cursor = Cursor::new(Vec::new());

    {
        let mut writer = zip::ZipWriter::new(&mut cursor);

        for file in &files {
            let mode = if executable_paths.contains(&file.path) {
                0o755
            } else {
                ARCHIVE_FILE_MODE
            };
            let file_options = options.unix_permissions(mode);

            writer
                .start_file(&file.path, file_options)
                .map_err(|e| PackageError::Archive(e.to_string()))?;

            writer
                .write_all(&file.contents)
                .map_err(|e| PackageError::Archive(e.to_string()))?;
        }

        writer
            .start_file(PACKAGE_MANIFEST_FILE, options)
            .map_err(|e| PackageError::Archive(e.to_string()))?;

        writer
            .write_all(&manifest_bytes)
            .map_err(|e| PackageError::Archive(e.to_string()))?;

        writer
            .finish()
            .map_err(|e| PackageError::Archive(e.to_string()))?;
    }

    let archive_bytes = cursor.into_inner();

    if archive_bytes.len() > limits.max_archive_bytes {
        return Err(PackageError::InvalidMetadata(
            "built archive exceeds maximum compressed size".into(),
        ));
    }

    let archive_sha256 = aip_crypto::sha256(&archive_bytes);

    Ok(BuiltPackage {
        manifest,
        manifest_bytes,
        archive_bytes,
        archive_sha256,
    })
}

/// Detached publisher signature for a built package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageSignature {
    pub signature: aip_types::Signature,
}

/// Version of the portable, unsigned export envelope. This is distinct from
/// the signed package format version in [`PackageManifest`].
pub const PACKAGE_EXPORT_VERSION: u16 = 1;

/// Strict wire representation of the existing AIP signature envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortableSignature {
    pub algorithm: aip_types::AlgorithmId,
    pub signer_id: String,
    pub timestamp: u64,
    pub nonce: [u8; 16],
    pub payload_hash: [u8; 32],
    pub signature_bytes: Vec<u8>,
}

impl From<&aip_types::Signature> for PortableSignature {
    fn from(s: &aip_types::Signature) -> Self {
        Self {
            algorithm: s.algorithm,
            signer_id: s.signer_id.clone(),
            timestamp: s.timestamp,
            nonce: s.nonce,
            payload_hash: s.payload_hash,
            signature_bytes: s.signature_bytes.clone(),
        }
    }
}

impl From<PortableSignature> for aip_types::Signature {
    fn from(s: PortableSignature) -> Self {
        Self {
            algorithm: s.algorithm,
            signer_id: s.signer_id,
            timestamp: s.timestamp,
            nonce: s.nonce,
            payload_hash: s.payload_hash,
            signature_bytes: s.signature_bytes,
        }
    }
}

/// Portable JSON envelope. `archive_base64` decodes to the exact ZIP bytes;
/// its detached signature remains the existing AIP package signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortablePackageExport {
    pub export_version: u16,
    pub package_format_version: u16,
    pub publisher_id: String,
    pub archive_sha256: String,
    pub manifest: PackageManifest,
    pub archive_base64: String,
    pub signature: PortableSignature,
}

/// External publisher trust anchor. This object must be provisioned
/// independently of the package export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublisherTrustAnchor {
    pub publisher_id: String,
    pub public_key_hex: String,
}

/// Convert an in-memory package and its existing detached signature to the
/// documented portable export representation.
pub fn export_package(
    package: &BuiltPackage,
    signature: &PackageSignature,
) -> Result<PortablePackageExport, PackageError> {
    let actual = aip_crypto::sha256(&package.archive_bytes);
    if actual != package.archive_sha256 {
        return Err(PackageError::InvalidMetadata(
            "archive digest does not match archive bytes".into(),
        ));
    }
    if package.manifest.format_version != PACKAGE_FORMAT_VERSION
        && package.manifest.format_version != PACKAGE_FORMAT_VERSION_V2
    {
        return Err(PackageError::InvalidMetadata(
            "unsupported package format version".into(),
        ));
    }
    Ok(PortablePackageExport {
        export_version: PACKAGE_EXPORT_VERSION,
        package_format_version: package.manifest.format_version,
        publisher_id: package.manifest.publisher_id.clone(),
        archive_sha256: hex::encode(actual),
        manifest: package.manifest.clone(),
        archive_base64: base64::engine::general_purpose::STANDARD.encode(&package.archive_bytes),
        signature: PortableSignature::from(&signature.signature),
    })
}

/// Reconstruct the existing package types from a parsed portable export.
/// Schema checks here do not replace cryptographic verification; callers
/// must pass the result through `verify_package_contents` with an external
/// anchor and expected AIBOM digest.
pub fn package_from_export(
    export: PortablePackageExport,
) -> Result<(BuiltPackage, PackageSignature), PackageError> {
    if export.export_version != PACKAGE_EXPORT_VERSION {
        return Err(PackageError::InvalidMetadata(format!(
            "unsupported export version {}",
            export.export_version
        )));
    }
    if export.package_format_version != PACKAGE_FORMAT_VERSION
        && export.package_format_version != PACKAGE_FORMAT_VERSION_V2
    {
        return Err(PackageError::InvalidMetadata(format!(
            "unsupported package format version {}",
            export.package_format_version
        )));
    }
    if export.package_format_version != export.manifest.format_version
        || export.publisher_id != export.manifest.publisher_id
    {
        return Err(PackageError::InvalidMetadata(
            "export metadata does not match package manifest".into(),
        ));
    }
    validate_digest(&export.archive_sha256, "archive_sha256")?;
    if export.archive_sha256 != export.archive_sha256.to_ascii_lowercase() {
        return Err(PackageError::InvalidMetadata(
            "archive_sha256 must use lowercase hexadecimal".into(),
        ));
    }
    let archive_bytes = base64::engine::general_purpose::STANDARD
        .decode(&export.archive_base64)
        .map_err(|e| PackageError::Serialization(format!("invalid archive base64: {e}")))?;
    if archive_bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(PackageError::InvalidMetadata(
            "archive exceeds maximum compressed size".into(),
        ));
    }
    let archive_sha256: [u8; 32] = hex::decode(&export.archive_sha256)
        .map_err(|e| PackageError::Serialization(e.to_string()))?
        .try_into()
        .map_err(|_| PackageError::InvalidMetadata("invalid archive digest length".into()))?;
    let manifest_bytes = serde_json::to_vec(&export.manifest)
        .map_err(|e| PackageError::Serialization(e.to_string()))?;
    let package = BuiltPackage {
        manifest: export.manifest,
        manifest_bytes,
        archive_bytes,
        archive_sha256,
    };
    let signature = PackageSignature {
        signature: export.signature.into(),
    };
    Ok((package, signature))
}

const PACKAGE_SIGNATURE_DOMAIN: &[u8] = b"AIP-SIGNED-PACKAGE-V1\0";

fn package_signing_payload(
    manifest: &PackageManifest,
    archive_sha256: &[u8; 32],
) -> Result<Vec<u8>, PackageError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(PACKAGE_SIGNATURE_DOMAIN);

    let metadata =
        serde_json::to_vec(manifest).map_err(|e| PackageError::Serialization(e.to_string()))?;

    payload.extend_from_slice(&(metadata.len() as u64).to_be_bytes());
    payload.extend_from_slice(&metadata);
    payload.extend_from_slice(archive_sha256);

    Ok(payload)
}

/// Sign the package using the publisher's Custodian.
///
/// The publisher ID in the package manifest must match the requested
/// signer identity. The private key remains inside the Custodian.
pub fn sign_package(
    package: &BuiltPackage,
    custodian: &dyn aip_crypto::custody::Custodian,
) -> Result<PackageSignature, PackageError> {
    if package.manifest.publisher_id.trim().is_empty() {
        return Err(PackageError::InvalidMetadata(
            "publisher ID is empty".into(),
        ));
    }

    let actual_archive_digest = aip_crypto::sha256(&package.archive_bytes);

    if actual_archive_digest != package.archive_sha256 {
        return Err(PackageError::InvalidMetadata(
            "archive digest does not match archive bytes".into(),
        ));
    }

    let payload = package_signing_payload(&package.manifest, &actual_archive_digest)?;

    let signature = custodian
        .sign(&package.manifest.publisher_id, &payload)
        .map_err(|e| PackageError::Archive(format!("custodian signing failed: {e}")))?;

    Ok(PackageSignature { signature })
}

/// Verify package authenticity and integrity using an externally trusted
/// publisher public key and the expected AIBOM manifest digest.
///
/// This does not authorize installation or execution.
pub fn verify_package(
    package: &BuiltPackage,
    package_signature: &PackageSignature,
    trusted_publisher_public_key: &[u8],
    expected_aibom_manifest_sha256: &str,
) -> Result<(), PackageError> {
    verify_package_contents(
        package,
        package_signature,
        trusted_publisher_public_key,
        expected_aibom_manifest_sha256,
    )
    .map(|_| ())
}

/// Verify a package and return its payload only after all authenticity,
/// inventory, size, permission, and content-hash checks have succeeded.
pub fn verify_package_contents(
    package: &BuiltPackage,
    package_signature: &PackageSignature,
    trusted_publisher_public_key: &[u8],
    expected_aibom_manifest_sha256: &str,
) -> Result<VerifiedPackage, PackageError> {
    if package.archive_bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(PackageError::InvalidMetadata(
            "archive exceeds maximum compressed size".into(),
        ));
    }

    let actual_archive_digest = aip_crypto::sha256(&package.archive_bytes);

    if actual_archive_digest != package.archive_sha256 {
        return Err(PackageError::InvalidMetadata(
            "archive SHA-256 mismatch".into(),
        ));
    }

    validate_digest(
        expected_aibom_manifest_sha256,
        "expected_aibom_manifest_sha256",
    )?;

    if !package
        .manifest
        .aibom_manifest_sha256
        .eq_ignore_ascii_case(expected_aibom_manifest_sha256)
    {
        return Err(PackageError::InvalidMetadata(
            "AIBOM manifest digest mismatch".into(),
        ));
    }

    let mut archive = zip::ZipArchive::new(Cursor::new(&package.archive_bytes))
        .map_err(|e| PackageError::Archive(e.to_string()))?;

    if archive.len() > MAX_PACKAGE_ENTRIES + 1 {
        return Err(PackageError::InvalidMetadata(
            "archive contains too many entries".into(),
        ));
    }

    if archive.has_duplicate_names() {
        return Err(PackageError::InvalidMetadata(
            "archive contains duplicate ZIP entry names".into(),
        ));
    }

    let manifest_size = archive
        .by_name(PACKAGE_MANIFEST_FILE)
        .map_err(|e| PackageError::Archive(e.to_string()))?
        .size();

    if manifest_size > MAX_MANIFEST_BYTES {
        return Err(PackageError::InvalidMetadata(
            "embedded package manifest exceeds maximum size".into(),
        ));
    }

    let mut embedded_manifest = Vec::new();

    archive
        .by_name(PACKAGE_MANIFEST_FILE)
        .map_err(|e| PackageError::Archive(e.to_string()))?
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut embedded_manifest)
        .map_err(|e| PackageError::Archive(e.to_string()))?;

    if embedded_manifest.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(PackageError::InvalidMetadata(
            "embedded package manifest exceeds maximum size".into(),
        ));
    }

    let parsed_manifest: PackageManifest = serde_json::from_slice(&embedded_manifest)
        .map_err(|e| PackageError::Serialization(e.to_string()))?;

    if parsed_manifest != package.manifest || embedded_manifest != package.manifest_bytes {
        return Err(PackageError::InvalidMetadata(
            "embedded package manifest does not match package metadata".into(),
        ));
    }

    // Validate the manifest structure before trusting its inventory.
    if parsed_manifest.format_version != PACKAGE_FORMAT_VERSION
        && parsed_manifest.format_version != PACKAGE_FORMAT_VERSION_V2
    {
        return Err(PackageError::InvalidMetadata(
            "unsupported package format version".into(),
        ));
    }

    let mut expected_files = BTreeMap::new();

    for item in &parsed_manifest.files {
        validate_path(&item.path)?;
        validate_digest(&item.sha256, "file.sha256")?;

        if expected_files.insert(item.path.as_str(), item).is_some() {
            return Err(PackageError::DuplicatePath(item.path.clone()));
        }
    }

    let signature = &package_signature.signature;

    if signature.signer_id != package.manifest.publisher_id {
        return Err(PackageError::InvalidMetadata(
            "signature publisher ID mismatch".into(),
        ));
    }

    let payload = package_signing_payload(&parsed_manifest, &actual_archive_digest)?;
    let expected_payload_hash = aip_crypto::sha256(&payload);

    if signature.payload_hash != expected_payload_hash {
        return Err(PackageError::InvalidMetadata(
            "signature payload hash mismatch".into(),
        ));
    }

    let valid = aip_crypto::verify_ed25519(trusted_publisher_public_key, signature)
        .map_err(|e| PackageError::Archive(format!("signature verification error: {e:?}")))?;

    if !valid {
        return Err(PackageError::InvalidMetadata(
            "publisher signature is invalid".into(),
        ));
    }

    // Independently verify every ZIP entry against the signed inventory.
    let mut seen_paths = BTreeSet::new();
    let mut manifest_count = 0usize;
    let mut total_uncompressed_bytes = 0u64;
    let mut verified_files = Vec::with_capacity(expected_files.len());

    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|e| PackageError::Archive(e.to_string()))?;

        let path = entry
            .name()
            .map_err(|e| PackageError::Archive(e.to_string()))?
            .into_owned();

        if path == PACKAGE_MANIFEST_FILE {
            manifest_count += 1;

            if entry.is_dir() || entry.is_symlink() || !entry.is_file() {
                return Err(PackageError::InvalidMetadata(
                    "package manifest is not a regular file".into(),
                ));
            }

            continue;
        }

        validate_path(&path)?;

        if entry.is_dir() || entry.is_symlink() || !entry.is_file() {
            return Err(PackageError::InvalidMetadata(format!(
                "non-regular archive entry: {path}"
            )));
        }

        if !seen_paths.insert(path.clone()) {
            return Err(PackageError::DuplicatePath(path));
        }

        let expected = expected_files.get(path.as_str()).ok_or_else(|| {
            PackageError::InvalidMetadata(format!("unexpected archive entry: {path}"))
        })?;

        if parsed_manifest.format_version == PACKAGE_FORMAT_VERSION_V2 {
            let expected_mode = if expected.executable { 0o755 } else { 0o644 };
            let raw_mode = entry.unix_mode().ok_or_else(|| {
                PackageError::InvalidMetadata(format!(
                    "missing Unix permission metadata for v2 file: {path}"
                ))
            })?;

            if raw_mode & 0o7000 != 0 {
                return Err(PackageError::InvalidMetadata(format!(
                    "special permission bits are not permitted for v2 file: {path}"
                )));
            }

            let actual_mode = raw_mode & 0o777;
            if actual_mode != expected_mode {
                return Err(PackageError::InvalidMetadata(format!(
                    "file permission mismatch for {path}: expected {expected_mode:o}, got {actual_mode:o}"
                )));
            }
        }

        if parsed_manifest.format_version == PACKAGE_FORMAT_VERSION && expected.executable {
            return Err(PackageError::InvalidMetadata(
                "v1 manifest contains v2 executable metadata".into(),
            ));
        }

        if entry.size() > MAX_FILE_BYTES {
            return Err(PackageError::InvalidMetadata(format!(
                "file exceeds maximum uncompressed size: {path}"
            )));
        }

        if entry.size() != expected.size {
            return Err(PackageError::InvalidMetadata(format!(
                "file size mismatch: {path}"
            )));
        }

        let remaining_budget = MAX_TOTAL_UNCOMPRESSED_BYTES
            .checked_sub(total_uncompressed_bytes)
            .ok_or_else(|| {
                PackageError::InvalidMetadata("total uncompressed size overflow".into())
            })?;

        if entry.size() > remaining_budget {
            return Err(PackageError::InvalidMetadata(
                "package exceeds maximum total uncompressed size".into(),
            ));
        }

        let read_limit = MAX_FILE_BYTES.min(remaining_budget);

        let mut contents = Vec::new();

        entry
            .take(read_limit + 1)
            .read_to_end(&mut contents)
            .map_err(|e| PackageError::Archive(e.to_string()))?;

        if contents.len() as u64 > MAX_FILE_BYTES {
            return Err(PackageError::InvalidMetadata(format!(
                "file exceeds maximum uncompressed size: {path}"
            )));
        }

        if contents.len() as u64 > remaining_budget {
            return Err(PackageError::InvalidMetadata(
                "package exceeds maximum total uncompressed size".into(),
            ));
        }

        if contents.len() as u64 != expected.size {
            return Err(PackageError::InvalidMetadata(format!(
                "actual decompressed size mismatch: {path}"
            )));
        }

        total_uncompressed_bytes = total_uncompressed_bytes
            .checked_add(contents.len() as u64)
            .ok_or_else(|| {
                PackageError::InvalidMetadata("total uncompressed size overflow".into())
            })?;

        let actual_hash = hex::encode(aip_crypto::sha256(&contents));

        if actual_hash != expected.sha256 {
            return Err(PackageError::InvalidMetadata(format!(
                "file SHA-256 mismatch: {path}"
            )));
        }

        verified_files.push(VerifiedPackageFile {
            path,
            contents,
            executable: expected.executable,
        });
    }

    if manifest_count != 1 {
        return Err(PackageError::InvalidMetadata(
            "archive must contain exactly one package manifest".into(),
        ));
    }

    if seen_paths.len() != expected_files.len()
        || seen_paths
            .iter()
            .any(|path| !expected_files.contains_key(path.as_str()))
    {
        return Err(PackageError::InvalidMetadata(
            "archive entries do not match manifest inventory".into(),
        ));
    }

    Ok(VerifiedPackage {
        manifest: parsed_manifest,
        files: verified_files,
        archive_sha256: actual_archive_digest,
        manifest_sha256: aip_crypto::sha256(&embedded_manifest),
    })
}

#[cfg(test)]
mod builder_limit_tests {
    use super::*;

    fn small_limits() -> PackageLimits {
        PackageLimits {
            max_archive_bytes: 1024 * 1024,
            max_file_bytes: 4,
            max_total_uncompressed_bytes: 6,
            max_package_entries: 2,
            max_manifest_bytes: 1024 * 1024,
        }
    }

    fn file(path: &str, contents: &[u8]) -> PackageFile {
        PackageFile {
            path: path.into(),
            contents: contents.to_vec(),
        }
    }

    fn build_with_limits(
        files: Vec<PackageFile>,
        limits: PackageLimits,
    ) -> Result<BuiltPackage, PackageError> {
        build_package_with_limits(
            "test-agent",
            "1.0.0",
            "publisher-test",
            &"a".repeat(64),
            files,
            limits,
        )
    }

    #[test]
    fn rejects_file_above_configured_limit() {
        let result = build_with_limits(vec![file("model.bin", b"12345")], small_limits());

        assert!(matches!(result, Err(PackageError::InvalidMetadata(_))));
    }

    #[test]
    fn rejects_total_payload_above_configured_limit() {
        let result = build_with_limits(
            vec![file("a.bin", b"1234"), file("b.bin", b"567")],
            small_limits(),
        );

        assert!(matches!(result, Err(PackageError::InvalidMetadata(_))));
    }

    #[test]
    fn rejects_too_many_package_entries() {
        let result = build_with_limits(
            vec![
                file("a.bin", b"a"),
                file("b.bin", b"b"),
                file("c.bin", b"c"),
            ],
            small_limits(),
        );

        assert!(matches!(result, Err(PackageError::InvalidMetadata(_))));
    }

    #[test]
    fn rejects_manifest_above_configured_limit() {
        let mut limits = small_limits();
        limits.max_manifest_bytes = 1;

        let result = build_with_limits(vec![], limits);

        assert!(matches!(result, Err(PackageError::InvalidMetadata(_))));
    }

    #[test]
    fn rejects_archive_above_configured_limit() {
        let mut limits = small_limits();
        limits.max_archive_bytes = 1;

        let result = build_with_limits(vec![], limits);

        assert!(matches!(result, Err(PackageError::InvalidMetadata(_))));
    }
}
