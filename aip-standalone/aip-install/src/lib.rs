//! AIP Secure Package Lifecycle.
//!
//! Installation receipts attest to an installer's recorded installation.
//! They do not grant execution permission. Execution remains governed by
//! independently verified capability epochs and the enforcement layer.

pub mod linux;
pub use linux::{
    activate_staged_package, activate_staged_package_with_inventory, audit_activated_package,
    audit_persistent_installation, inspect_installation_recovery, rollback_to_release,
    stage_verified_package, upgrade_staged_package_with_inventory, ActivatedPackage, RecoveryEntry,
    RecoveryEntryKind, RecoveryReport, StagedPackage,
};

use aip_crypto::{custody::Custodian, sha256, verify_ed25519};
use aip_types::{
    canonical::{put_bytes, put_domain, put_str, put_u16, put_u64},
    AlgorithmId, Signature,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const INSTALL_RECEIPT_VERSION: u16 = 1;
pub const INSTALL_RECEIPT_DOMAIN: &str = "AIP/INSTALL_RECEIPT/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledExecutable {
    /// Relative path inside the installed package.
    pub path: String,
    /// SHA-256 of the installed executable's actual bytes.
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallReceipt {
    pub version: u16,
    pub installation_id: [u8; 16],
    pub installer_id: String,
    pub package_name: String,
    pub package_version: String,
    pub publisher_id: String,
    pub archive_sha256: [u8; 32],
    pub manifest_sha256: [u8; 32],
    pub aibom_manifest_sha256: [u8; 32],
    pub installed_at_ms: u64,
    /// Must be sorted by path and contain no duplicate paths.
    pub executables: Vec<InstalledExecutable>,
}

impl InstallReceipt {
    pub fn validate(&self) -> Result<(), InstallError> {
        if self.version != INSTALL_RECEIPT_VERSION {
            return Err(InstallError::UnsupportedVersion(self.version));
        }

        for (field, value) in [
            ("installer_id", self.installer_id.as_str()),
            ("package_name", self.package_name.as_str()),
            ("package_version", self.package_version.as_str()),
            ("publisher_id", self.publisher_id.as_str()),
        ] {
            if value.trim().is_empty() || value.len() > 256 {
                return Err(InstallError::InvalidField(field));
            }
        }

        let mut previous: Option<&str> = None;
        for executable in &self.executables {
            let path = executable.path.as_str();

            if path.is_empty()
                || path.starts_with('/')
                || path.contains('\\')
                || path
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
            {
                return Err(InstallError::InvalidExecutablePath(path.to_string()));
            }

            if let Some(prev) = previous {
                if prev >= path {
                    return Err(InstallError::ExecutableOrderOrDuplicate);
                }
            }
            previous = Some(path);
        }

        Ok(())
    }

    /// Unambiguous canonical bytes with a dedicated receipt domain.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_domain(&mut out, INSTALL_RECEIPT_DOMAIN);
        put_u16(&mut out, self.version);
        out.extend_from_slice(&self.installation_id);
        put_str(&mut out, &self.installer_id);
        put_str(&mut out, &self.package_name);
        put_str(&mut out, &self.package_version);
        put_str(&mut out, &self.publisher_id);
        out.extend_from_slice(&self.archive_sha256);
        out.extend_from_slice(&self.manifest_sha256);
        out.extend_from_slice(&self.aibom_manifest_sha256);
        put_u64(&mut out, self.installed_at_ms);
        put_u32(&mut out, self.executables.len() as u32);

        for executable in &self.executables {
            put_str(&mut out, &executable.path);
            put_bytes(&mut out, &executable.sha256);
        }

        out
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&self.canonical_bytes())
    }
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedInstallReceipt {
    pub receipt: InstallReceipt,
    pub signature: Signature,
}

pub const INSTALL_INVENTORY_VERSION: u16 = 1;
pub const INSTALL_INVENTORY_DOMAIN: &str = "AIP/INSTALL_INVENTORY/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentInventoryFile {
    pub path: String,
    pub sha256: [u8; 32],
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentInstallInventory {
    pub version: u16,
    pub installation_id: [u8; 16],
    pub installer_id: String,
    pub release_name: String,
    pub package_name: String,
    pub package_version: String,
    pub publisher_id: String,
    pub archive_sha256: [u8; 32],
    pub manifest_sha256: [u8; 32],
    pub aibom_manifest_sha256: [u8; 32],
    pub installed_at_ms: u64,
    pub files: Vec<PersistentInventoryFile>,
}

impl PersistentInstallInventory {
    pub fn validate(&self) -> Result<(), InstallError> {
        if self.version != INSTALL_INVENTORY_VERSION {
            return Err(InstallError::UnsupportedVersion(self.version));
        }

        for (field, value) in [
            ("installer_id", self.installer_id.as_str()),
            ("release_name", self.release_name.as_str()),
            ("package_name", self.package_name.as_str()),
            ("package_version", self.package_version.as_str()),
            ("publisher_id", self.publisher_id.as_str()),
        ] {
            if value.trim().is_empty() || value.len() > 256 {
                return Err(InstallError::InvalidField(field));
            }
        }

        if !self.release_name.starts_with("release-")
            || self.release_name.contains('/')
            || self.release_name.contains('\\')
            || self.release_name == "."
            || self.release_name == ".."
        {
            return Err(InstallError::InvalidField("release_name"));
        }

        let mut previous: Option<&str> = None;
        for file in &self.files {
            let path = file.path.as_str();
            if path.is_empty()
                || path.starts_with('/')
                || path.contains('\\')
                || path
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
            {
                return Err(InstallError::InvalidExecutablePath(path.to_string()));
            }
            if let Some(prev) = previous {
                if prev >= path {
                    return Err(InstallError::ExecutableOrderOrDuplicate);
                }
            }
            previous = Some(path);
        }

        Ok(())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_domain(&mut out, INSTALL_INVENTORY_DOMAIN);
        put_u16(&mut out, self.version);
        out.extend_from_slice(&self.installation_id);
        put_str(&mut out, &self.installer_id);
        put_str(&mut out, &self.release_name);
        put_str(&mut out, &self.package_name);
        put_str(&mut out, &self.package_version);
        put_str(&mut out, &self.publisher_id);
        out.extend_from_slice(&self.archive_sha256);
        out.extend_from_slice(&self.manifest_sha256);
        out.extend_from_slice(&self.aibom_manifest_sha256);
        put_u64(&mut out, self.installed_at_ms);
        put_u32(&mut out, self.files.len() as u32);

        for file in &self.files {
            put_str(&mut out, &file.path);
            out.extend_from_slice(&file.sha256);
            out.push(u8::from(file.executable));
        }

        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPersistentInstallInventory {
    pub inventory: PersistentInstallInventory,
    pub signature: Signature,
}

pub fn sign_persistent_install_inventory(
    inventory: PersistentInstallInventory,
    custodian: &dyn Custodian,
) -> Result<SignedPersistentInstallInventory, InstallError> {
    inventory.validate()?;
    let payload = inventory.canonical_bytes();
    let signature = custodian
        .sign(&inventory.installer_id, &payload)
        .map_err(|e| InstallError::Crypto(format!("{e:?}")))?;

    if signature.algorithm != AlgorithmId::Ed25519 {
        return Err(InstallError::AlgorithmMismatch);
    }
    if signature.signer_id != inventory.installer_id {
        return Err(InstallError::SignerMismatch);
    }
    if signature.payload_hash != sha256(&payload) {
        return Err(InstallError::PayloadHashMismatch);
    }

    match verify_ed25519(custodian.public_key(), &signature) {
        Ok(true) => Ok(SignedPersistentInstallInventory {
            inventory,
            signature,
        }),
        Ok(false) => Err(InstallError::InvalidSignature),
        Err(e) => Err(InstallError::Crypto(format!("{e:?}"))),
    }
}

pub fn verify_persistent_install_inventory<'a>(
    signed: &'a SignedPersistentInstallInventory,
    trusted_installer_public_key: &[u8],
) -> Result<&'a PersistentInstallInventory, InstallError> {
    signed.inventory.validate()?;

    if signed.signature.algorithm != AlgorithmId::Ed25519 {
        return Err(InstallError::AlgorithmMismatch);
    }
    if signed.signature.signer_id != signed.inventory.installer_id {
        return Err(InstallError::SignerMismatch);
    }

    let payload = signed.inventory.canonical_bytes();
    if signed.signature.payload_hash != sha256(&payload) {
        return Err(InstallError::PayloadHashMismatch);
    }

    match verify_ed25519(trusted_installer_public_key, &signed.signature) {
        Ok(true) => Ok(&signed.inventory),
        Ok(false) => Err(InstallError::InvalidSignature),
        Err(e) => Err(InstallError::Crypto(format!("{e:?}"))),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallError {
    UnsupportedVersion(u16),
    InvalidField(&'static str),
    InvalidExecutablePath(String),
    ExecutableOrderOrDuplicate,
    SignerMismatch,
    AlgorithmMismatch,
    PayloadHashMismatch,
    InvalidSignature,
    DigestMismatch,
    Io(String),
    Crypto(String),
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for InstallError {}

/// Sign an installation record using the existing AIP Custodian.
///
/// This function records an installation claim. It does not authorize
/// execution or prove independent observation of the installed files.
pub fn sign_install_receipt(
    receipt: InstallReceipt,
    custodian: &dyn Custodian,
) -> Result<SignedInstallReceipt, InstallError> {
    receipt.validate()?;

    let payload = receipt.canonical_bytes();
    let signature = custodian
        .sign(&receipt.installer_id, &payload)
        .map_err(|e| InstallError::Crypto(format!("{e:?}")))?;

    if signature.algorithm != AlgorithmId::Ed25519 {
        return Err(InstallError::AlgorithmMismatch);
    }
    if signature.signer_id != receipt.installer_id {
        return Err(InstallError::SignerMismatch);
    }
    if signature.payload_hash != sha256(&payload) {
        return Err(InstallError::PayloadHashMismatch);
    }

    match verify_ed25519(custodian.public_key(), &signature) {
        Ok(true) => Ok(SignedInstallReceipt { receipt, signature }),
        Ok(false) => Err(InstallError::InvalidSignature),
        Err(e) => Err(InstallError::Crypto(format!("{e:?}"))),
    }
}

/// Create and sign an installation receipt from an activated package.
///
/// The installation ID is generated randomly and the timestamp is taken
/// from the system clock. The receipt records the installer's claim; it is
/// not independent proof of execution or authorization to execute.
pub fn create_signed_install_receipt(
    activated: &linux::ActivatedPackage,
    installer_id: &str,
    custodian: &dyn Custodian,
) -> Result<SignedInstallReceipt, InstallError> {
    let installed_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| InstallError::Io(format!("system clock before Unix epoch: {error}")))?
        .as_millis();

    let installed_at_ms = u64::try_from(installed_at_ms)
        .map_err(|_| InstallError::InvalidField("installed_at_ms"))?;

    let mut installation_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut installation_id);

    let receipt = InstallReceipt {
        version: INSTALL_RECEIPT_VERSION,
        installation_id,
        installer_id: installer_id.to_string(),
        package_name: activated.package_name().to_string(),
        package_version: activated.package_version().to_string(),
        publisher_id: activated.publisher_id().to_string(),
        archive_sha256: *activated.archive_sha256(),
        manifest_sha256: *activated.manifest_sha256(),
        aibom_manifest_sha256: *activated.aibom_manifest_sha256(),
        installed_at_ms,
        executables: activated.executables().to_vec(),
    };

    sign_install_receipt(receipt, custodian)
}

/// Verify the receipt against an independently trusted installer key.
pub fn verify_install_receipt<'a>(
    signed: &'a SignedInstallReceipt,
    trusted_installer_public_key: &[u8],
) -> Result<&'a InstallReceipt, InstallError> {
    signed.receipt.validate()?;

    if signed.signature.algorithm != AlgorithmId::Ed25519 {
        return Err(InstallError::AlgorithmMismatch);
    }
    if signed.signature.signer_id != signed.receipt.installer_id {
        return Err(InstallError::SignerMismatch);
    }

    let payload = signed.receipt.canonical_bytes();
    if signed.signature.payload_hash != sha256(&payload) {
        return Err(InstallError::PayloadHashMismatch);
    }

    match verify_ed25519(trusted_installer_public_key, &signed.signature) {
        Ok(true) => Ok(&signed.receipt),
        Ok(false) => Err(InstallError::InvalidSignature),
        Err(e) => Err(InstallError::Crypto(format!("{e:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aip_crypto::custody::InMemoryCustodian;

    fn sample_receipt() -> InstallReceipt {
        InstallReceipt {
            version: INSTALL_RECEIPT_VERSION,
            installation_id: [7; 16],
            installer_id: "installer-test".into(),
            package_name: "test-agent".into(),
            package_version: "1.0.0".into(),
            publisher_id: "publisher-test".into(),
            archive_sha256: [1; 32],
            manifest_sha256: [2; 32],
            aibom_manifest_sha256: [3; 32],
            installed_at_ms: 1_800_000_000_000,
            executables: vec![InstalledExecutable {
                path: "bin/agent".into(),
                sha256: [4; 32],
            }],
        }
    }

    #[test]
    fn signed_receipt_verifies() {
        let signer = InMemoryCustodian::generate();
        let signed = sign_install_receipt(sample_receipt(), &signer).unwrap();

        let verified = verify_install_receipt(&signed, signer.public_key()).unwrap();

        assert_eq!(verified.package_name, "test-agent");
    }

    #[test]
    fn modified_receipt_is_rejected() {
        let signer = InMemoryCustodian::generate();
        let mut signed = sign_install_receipt(sample_receipt(), &signer).unwrap();

        signed.receipt.archive_sha256 = [9; 32];

        assert_eq!(
            verify_install_receipt(&signed, signer.public_key()),
            Err(InstallError::PayloadHashMismatch)
        );
    }

    #[test]
    fn wrong_trusted_key_is_rejected() {
        let signer = InMemoryCustodian::generate();
        let other = InMemoryCustodian::generate();
        let signed = sign_install_receipt(sample_receipt(), &signer).unwrap();

        assert_eq!(
            verify_install_receipt(&signed, other.public_key()),
            Err(InstallError::InvalidSignature)
        );
    }

    #[test]
    fn signer_identity_mismatch_is_rejected() {
        let signer = InMemoryCustodian::generate();
        let mut signed = sign_install_receipt(sample_receipt(), &signer).unwrap();

        signed.signature.signer_id = "someone-else".into();

        assert_eq!(
            verify_install_receipt(&signed, signer.public_key()),
            Err(InstallError::SignerMismatch)
        );
    }

    #[test]
    fn traversal_paths_are_rejected() {
        let mut receipt = sample_receipt();
        receipt.executables[0].path = "../outside".into();

        assert_eq!(
            receipt.validate(),
            Err(InstallError::InvalidExecutablePath("../outside".into()))
        );
    }

    #[test]
    fn executable_order_must_be_canonical() {
        let mut receipt = sample_receipt();
        receipt.executables = vec![
            InstalledExecutable {
                path: "z".into(),
                sha256: [1; 32],
            },
            InstalledExecutable {
                path: "a".into(),
                sha256: [2; 32],
            },
        ];

        assert_eq!(
            receipt.validate(),
            Err(InstallError::ExecutableOrderOrDuplicate)
        );
    }
}
