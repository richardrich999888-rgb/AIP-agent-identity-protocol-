//! Offline core for transferring existing signed AIP package exports.
//!
//! The transfer manifest is signed by the package publisher through an AIP
//! [`Custodian`]. Its key is supplied independently by the verifier. This
//! signature authenticates transfer metadata only; the existing package
//! verifier remains authoritative for publisher authenticity. The
//! higher-level integration must validate an AIBOM manifest and detached
//! seal against an external anchor, then pass its canonical digest here.

use aip_crypto::{custody::Custodian, sha256, verify_ed25519};
use aip_package::{
    package_from_export, verify_package_contents, PortablePackageExport, VerifiedPackage,
};
use serde::{Deserialize, Serialize};
use std::fmt;

#[cfg(feature = "p2p")]
pub mod authorization;
pub mod evidence;
#[cfg(feature = "live-noise")]
pub mod network_protocol;
#[cfg(feature = "p2p")]
pub mod peer_binding;
#[cfg(all(feature = "live-noise", unix))]
pub mod persistent_replay;
pub mod revocation_snapshot;

#[cfg(unix)]
mod disk;
#[cfg(unix)]
pub use disk::DiskTransferReceiver;

#[cfg(not(unix))]
pub struct DiskTransferReceiver;
#[cfg(not(unix))]
impl DiskTransferReceiver {
    pub fn create<P: AsRef<std::path::Path>>(
        _: P,
        _: TransferManifest,
        _: &str,
        _: &[u8],
    ) -> Result<Self> {
        Err(DistributionError::Invalid(
            "disk receiver is unavailable on this platform; secure no-follow file operations are not implemented".into(),
        ))
    }
    pub fn resume<P: AsRef<std::path::Path>>(_: P, _: &str, _: &[u8]) -> Result<Self> {
        Err(DistributionError::Invalid(
            "disk receiver is unavailable on this platform; secure no-follow file operations are not implemented".into(),
        ))
    }
    pub fn accept(&mut self, _: TransferChunk) -> Result<()> {
        Err(DistributionError::Invalid(
            "disk receiver is unavailable on this platform".into(),
        ))
    }
    pub fn completed_chunks(&self) -> usize {
        0
    }
    pub fn transfer_id(&self) -> &str {
        ""
    }
    pub fn finalize(self, _: &str, _: &[u8], _: &str) -> Result<VerifiedPackage> {
        Err(DistributionError::Invalid(
            "disk receiver is unavailable on this platform".into(),
        ))
    }
    pub fn partial_directory(&self) -> &std::path::Path {
        std::path::Path::new("")
    }
}

pub const MANIFEST_VERSION: u16 = 1;
pub const CHUNK_SIZE: usize = 256 * 1024;
pub const MAX_TRANSFER_BYTES: u64 = 400 * 1024 * 1024;
pub const MAX_MANIFEST_JSON_BYTES: usize = 8 * 1024;
const ID_DOMAIN: &[u8] = b"AIP-DISTRIBUTION-TRANSFER-ID-v1\0";
const SIGN_DOMAIN: &[u8] = b"AIP-DISTRIBUTION-MANIFEST-SIGN-v1\0";
const LEAF_DOMAIN: &[u8] = b"AIP-DISTRIBUTION-LEAF-v1\0";
const NODE_DOMAIN: &[u8] = b"AIP-DISTRIBUTION-NODE-v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistributionError {
    Invalid(String),
    Crypto(String),
    Package(String),
    Aibom(String),
}
impl fmt::Display for DistributionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DistributionError {}
type Result<T> = std::result::Result<T, DistributionError>;

/// Signed descriptor for the exact portable package-export bytes.
/// Canonical bytes are a fixed-order binary encoding, not JSON. Strings use
/// u32 big-endian byte-length prefixes; integers use big endian.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransferManifest {
    pub version: u16,
    pub transfer_id: String,
    pub publisher_id: String,
    pub package_name: String,
    pub package_version: String,
    pub package_format_version: u16,
    pub export_len: u64,
    pub export_sha256: String,
    pub archive_sha256: String,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub merkle_root: String,
    pub signature: aip_types::Signature,
}

/// Parse the transport JSON representation with a hard input ceiling and
/// strict unknown-field rejection. Signature verification is a separate
/// required step through [`verify_manifest`].
pub fn parse_manifest(bytes: &[u8]) -> Result<TransferManifest> {
    if bytes.len() > MAX_MANIFEST_JSON_BYTES {
        return Err(DistributionError::Invalid(
            "transfer manifest exceeds maximum encoded size".into(),
        ));
    }
    serde_json::from_slice(bytes)
        .map_err(|e| DistributionError::Invalid(format!("malformed transfer manifest: {e}")))
}

/// Indexed chunk and its bottom-up sibling path. Odd nodes are duplicated at
/// each level; their proof therefore contains the current hash as sibling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransferChunk {
    pub index: u32,
    pub bytes: Vec<u8>,
    pub proof: Vec<String>,
}

/// Portable restart state. It is untrusted input: `resume` rechecks the
/// manifest signature, order, lengths, transfer bounds and every proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResumeState {
    pub manifest: TransferManifest,
    pub chunks: Vec<TransferChunk>,
}

fn put_u16(out: &mut Vec<u8>, n: u16) {
    out.extend_from_slice(&n.to_be_bytes());
}
fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_be_bytes());
}
fn put_str(out: &mut Vec<u8>, s: &str) -> Result<()> {
    let len =
        u32::try_from(s.len()).map_err(|_| DistributionError::Invalid("string too long".into()))?;
    put_u32(out, len);
    out.extend_from_slice(s.as_bytes());
    Ok(())
}
fn digest_field(s: &str, field: &str) -> Result<[u8; 32]> {
    if s != s.to_ascii_lowercase() {
        return Err(DistributionError::Invalid(format!(
            "{field} must use lowercase hexadecimal"
        )));
    }
    let bytes =
        hex::decode(s).map_err(|_| DistributionError::Invalid(format!("malformed {field}")))?;
    bytes
        .try_into()
        .map_err(|_| DistributionError::Invalid(format!("malformed {field}")))
}
fn validate_label(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(DistributionError::Invalid(format!(
            "invalid {field} length or characters"
        )));
    }
    Ok(())
}

/// Canonical unsigned signing payload. `transfer_id` derives only from exact
/// export length/digest and fixed chunking parameters (no root or signature);
/// the signed payload then binds the Merkle root and all package metadata.
pub fn manifest_signing_bytes(m: &TransferManifest) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    b.extend_from_slice(SIGN_DOMAIN);
    put_u16(&mut b, m.version);
    put_str(&mut b, &m.transfer_id)?;
    put_str(&mut b, &m.publisher_id)?;
    put_str(&mut b, &m.package_name)?;
    put_str(&mut b, &m.package_version)?;
    put_u16(&mut b, m.package_format_version);
    put_u64(&mut b, m.export_len);
    b.extend_from_slice(&digest_field(&m.export_sha256, "export_sha256")?);
    b.extend_from_slice(&digest_field(&m.archive_sha256, "archive_sha256")?);
    put_u32(&mut b, m.chunk_size);
    put_u32(&mut b, m.chunk_count);
    b.extend_from_slice(&digest_field(&m.merkle_root, "merkle_root")?);
    Ok(b)
}

fn transfer_id(len: u64, export_digest: &[u8; 32]) -> String {
    let mut b = ID_DOMAIN.to_vec();
    put_u64(&mut b, len);
    b.extend_from_slice(export_digest);
    put_u32(&mut b, CHUNK_SIZE as u32);
    hex::encode(sha256(&b))
}
fn expected_count(len: u64, size: u32) -> Result<u32> {
    if len == 0 || len > MAX_TRANSFER_BYTES || size as usize != CHUNK_SIZE {
        return Err(DistributionError::Invalid(
            "unsupported transfer size or chunk size".into(),
        ));
    }
    let n = len
        .checked_add(size as u64 - 1)
        .ok_or_else(|| DistributionError::Invalid("chunk count overflow".into()))?
        / size as u64;
    u32::try_from(n).map_err(|_| DistributionError::Invalid("too many chunks".into()))
}
fn leaf(id: &str, index: u32, bytes: &[u8]) -> Result<[u8; 32]> {
    let mut b = LEAF_DOMAIN.to_vec();
    b.extend_from_slice(&digest_field(id, "transfer_id")?);
    put_u64(&mut b, u64::from(index));
    put_u32(
        &mut b,
        u32::try_from(bytes.len())
            .map_err(|_| DistributionError::Invalid("chunk too large".into()))?,
    );
    b.extend_from_slice(bytes);
    Ok(sha256(&b))
}
fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut b = NODE_DOMAIN.to_vec();
    b.extend_from_slice(left);
    b.extend_from_slice(right);
    sha256(&b)
}
fn tree(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    let mut levels = vec![leaves.to_vec()];
    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next = Vec::with_capacity((prev.len() + 1) / 2);
        for pair in prev.chunks(2) {
            next.push(node(&pair[0], pair.get(1).unwrap_or(&pair[0])));
        }
        levels.push(next);
    }
    levels
}
fn proof(levels: &[Vec<[u8; 32]>], mut i: usize) -> Vec<String> {
    let mut out = Vec::new();
    for level in &levels[..levels.len() - 1] {
        let sibling = if i % 2 == 0 {
            *level.get(i + 1).unwrap_or(&level[i])
        } else {
            level[i - 1]
        };
        out.push(hex::encode(sibling));
        i /= 2;
    }
    out
}

/// Build and publisher-sign a descriptor for exact serialized portable export bytes.
pub fn create_manifest(
    export_bytes: &[u8],
    custodian: &dyn Custodian,
) -> Result<(TransferManifest, Vec<TransferChunk>)> {
    let len = u64::try_from(export_bytes.len())
        .map_err(|_| DistributionError::Invalid("export length overflow".into()))?;
    let count = expected_count(len, CHUNK_SIZE as u32)?;
    let export: PortablePackageExport = serde_json::from_slice(export_bytes)
        .map_err(|e| DistributionError::Invalid(format!("malformed package export: {e}")))?;
    if export.publisher_id.trim().is_empty()
        || export.package_format_version != export.manifest.format_version
    {
        return Err(DistributionError::Invalid(
            "inconsistent package export metadata".into(),
        ));
    }
    let mut m = TransferManifest {
        version: MANIFEST_VERSION,
        transfer_id: transfer_id(len, &sha256(export_bytes)),
        publisher_id: export.publisher_id.clone(),
        package_name: export.manifest.name.clone(),
        package_version: export.manifest.version.clone(),
        package_format_version: export.package_format_version,
        export_len: len,
        export_sha256: hex::encode(sha256(export_bytes)),
        archive_sha256: export.archive_sha256.clone(),
        chunk_size: CHUNK_SIZE as u32,
        chunk_count: count,
        merkle_root: String::new(),
        signature: placeholder(&export.publisher_id),
    };
    let parts: Vec<&[u8]> = export_bytes.chunks(CHUNK_SIZE).collect();
    let leaves: Vec<[u8; 32]> = parts
        .iter()
        .enumerate()
        .map(|(i, b)| leaf(&m.transfer_id, i as u32, b))
        .collect::<Result<_>>()?;
    let levels = tree(&leaves);
    m.merkle_root = hex::encode(levels.last().unwrap()[0]);
    let payload = manifest_signing_bytes(&m)?;
    m.signature = custodian
        .sign(&m.publisher_id, &payload)
        .map_err(|e| DistributionError::Crypto(format!("custodian failed: {e}")))?;
    let chunks = parts
        .iter()
        .enumerate()
        .map(|(i, b)| TransferChunk {
            index: i as u32,
            bytes: b.to_vec(),
            proof: proof(&levels, i),
        })
        .collect();
    Ok((m, chunks))
}
fn placeholder(id: &str) -> aip_types::Signature {
    aip_types::Signature {
        algorithm: aip_types::AlgorithmId::Ed25519,
        signer_id: id.to_owned(),
        timestamp: 0,
        nonce: [0; 16],
        payload_hash: [0; 32],
        signature_bytes: vec![],
    }
}

pub fn verify_manifest(
    m: &TransferManifest,
    trusted_publisher_id: &str,
    trusted_key: &[u8],
) -> Result<()> {
    if m.version != MANIFEST_VERSION
        || m.publisher_id != trusted_publisher_id
        || m.signature.signer_id != m.publisher_id
    {
        return Err(DistributionError::Invalid(
            "unsupported manifest or untrusted publisher identity".into(),
        ));
    }
    validate_label(&m.publisher_id, "publisher_id")?;
    validate_label(&m.package_name, "package_name")?;
    validate_label(&m.package_version, "package_version")?;
    if m.transfer_id
        != transfer_id(
            m.export_len,
            &digest_field(&m.export_sha256, "export_sha256")?,
        )
        || m.chunk_count != expected_count(m.export_len, m.chunk_size)?
    {
        return Err(DistributionError::Invalid(
            "invalid transfer identity or chunk count".into(),
        ));
    }
    digest_field(&m.archive_sha256, "archive_sha256")?;
    digest_field(&m.merkle_root, "merkle_root")?;
    if m.signature.payload_hash != sha256(&manifest_signing_bytes(m)?) {
        return Err(DistributionError::Invalid(
            "manifest payload hash mismatch".into(),
        ));
    }
    match verify_ed25519(trusted_key, &m.signature) {
        Ok(true) => Ok(()),
        Ok(false) => Err(DistributionError::Invalid(
            "invalid transfer manifest signature".into(),
        )),
        Err(e) => Err(DistributionError::Crypto(format!(
            "signature verification: {e:?}"
        ))),
    }
}

pub fn verify_chunk(m: &TransferManifest, c: &TransferChunk) -> Result<()> {
    if m.version != MANIFEST_VERSION || m.chunk_count != expected_count(m.export_len, m.chunk_size)?
    {
        return Err(DistributionError::Invalid(
            "invalid manifest chunk parameters".into(),
        ));
    }
    if c.index >= m.chunk_count {
        return Err(DistributionError::Invalid(
            "chunk index out of range".into(),
        ));
    }
    let offset = u64::from(c.index)
        .checked_mul(u64::from(m.chunk_size))
        .ok_or_else(|| DistributionError::Invalid("chunk offset overflow".into()))?;
    let remain = m
        .export_len
        .checked_sub(offset)
        .ok_or_else(|| DistributionError::Invalid("chunk offset beyond export".into()))?;
    let expected = usize::try_from(remain.min(u64::from(m.chunk_size)))
        .map_err(|_| DistributionError::Invalid("chunk length overflow".into()))?;
    if c.bytes.len() != expected {
        return Err(DistributionError::Invalid("incorrect chunk length".into()));
    }
    let mut current = leaf(&m.transfer_id, c.index, &c.bytes)?;
    let mut idx = c.index as usize;
    let mut width = m.chunk_count as usize;
    let mut p = 0;
    while width > 1 {
        if p >= c.proof.len() {
            return Err(DistributionError::Invalid("short Merkle proof".into()));
        }
        let sibling = digest_field(&c.proof[p], "proof sibling")?;
        if idx % 2 == 0 {
            if idx + 1 >= width && sibling != current {
                return Err(DistributionError::Invalid(
                    "odd-leaf sibling must duplicate leaf".into(),
                ));
            }
            current = node(&current, &sibling);
        } else {
            current = node(&sibling, &current);
        }
        idx /= 2;
        width = (width + 1) / 2;
        p += 1;
    }
    if p != c.proof.len() || hex::encode(current) != m.merkle_root {
        return Err(DistributionError::Invalid("invalid Merkle proof".into()));
    }
    Ok(())
}

/// Sequential receiver. It accepts only the next exact index; callers may
/// fetch out of order, but must verify and reorder in a bounded staging layer
/// before submission. No output is exposed until all checks pass.
pub struct TransferReceiver {
    manifest: TransferManifest,
    chunks: Vec<TransferChunk>,
    total: u64,
}
impl TransferReceiver {
    pub fn new(
        manifest: TransferManifest,
        publisher_id: &str,
        publisher_key: &[u8],
    ) -> Result<Self> {
        verify_manifest(&manifest, publisher_id, publisher_key)?;
        Ok(Self {
            manifest,
            chunks: Vec::new(),
            total: 0,
        })
    }
    pub fn accept(&mut self, c: TransferChunk) -> Result<()> {
        let expected = self.chunks.len();
        if usize::try_from(c.index).ok() != Some(expected) {
            return Err(DistributionError::Invalid(
                "duplicate, missing, or reordered chunk".into(),
            ));
        }
        verify_chunk(&self.manifest, &c)?;
        self.total = self
            .total
            .checked_add(c.bytes.len() as u64)
            .ok_or_else(|| DistributionError::Invalid("received byte count overflow".into()))?;
        if self.total > self.manifest.export_len {
            return Err(DistributionError::Invalid(
                "transfer exceeds declared length".into(),
            ));
        }
        self.chunks.push(c);
        Ok(())
    }
    pub fn resume_state(&self) -> ResumeState {
        ResumeState {
            manifest: self.manifest.clone(),
            chunks: self.chunks.clone(),
        }
    }
    pub fn resume(state: ResumeState, publisher_id: &str, publisher_key: &[u8]) -> Result<Self> {
        let mut r = Self::new(state.manifest, publisher_id, publisher_key)?;
        for c in state.chunks {
            r.accept(c)?;
        }
        Ok(r)
    }
    pub fn verify_complete(
        self,
        package_publisher_id: &str,
        package_publisher_key: &[u8],
        independently_verified_aibom_digest: &str,
    ) -> Result<VerifiedPackage> {
        if self.chunks.len() != self.manifest.chunk_count as usize
            || self.total != self.manifest.export_len
        {
            return Err(DistributionError::Invalid("incomplete transfer".into()));
        }
        let mut bytes = Vec::with_capacity(
            usize::try_from(self.total)
                .map_err(|_| DistributionError::Invalid("transfer allocation overflow".into()))?,
        );
        for c in &self.chunks {
            bytes.extend_from_slice(&c.bytes);
        }
        verify_export_bytes(
            &self.manifest,
            package_publisher_id,
            package_publisher_key,
            independently_verified_aibom_digest,
            &bytes,
        )
    }
}

fn verify_export_bytes(
    manifest: &TransferManifest,
    package_publisher_id: &str,
    package_publisher_key: &[u8],
    independently_verified_aibom_digest: &str,
    bytes: &[u8],
) -> Result<VerifiedPackage> {
    if manifest.publisher_id != package_publisher_id {
        return Err(DistributionError::Invalid(
            "transfer publisher does not match trusted package publisher".into(),
        ));
    }
    if independently_verified_aibom_digest.len() != 64
        || !independently_verified_aibom_digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(DistributionError::Aibom(
            "expected AIBOM digest must be lowercase SHA-256 hex from an independently verified artifact".into(),
        ));
    }
    if u64::try_from(bytes.len()).ok() != Some(manifest.export_len)
        || hex::encode(sha256(bytes)) != manifest.export_sha256
    {
        return Err(DistributionError::Invalid(
            "assembled export digest mismatch".into(),
        ));
    }
    let export: PortablePackageExport = serde_json::from_slice(bytes)
        .map_err(|e| DistributionError::Invalid(format!("malformed assembled export: {e}")))?;
    if export.publisher_id != manifest.publisher_id
        || export.manifest.name != manifest.package_name
        || export.manifest.version != manifest.package_version
        || export.package_format_version != manifest.package_format_version
        || export.archive_sha256 != manifest.archive_sha256
    {
        return Err(DistributionError::Invalid(
            "transfer/package metadata mismatch".into(),
        ));
    }
    let (package, signature) =
        package_from_export(export).map_err(|e| DistributionError::Package(e.to_string()))?;
    verify_package_contents(
        &package,
        &signature,
        package_publisher_key,
        independently_verified_aibom_digest,
    )
    .map_err(|e| DistributionError::Package(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn id_excludes_root_and_signature_but_binds_export() {
        let d = sha256(b"bytes");
        assert_eq!(transfer_id(5, &d), transfer_id(5, &d));
        assert_ne!(transfer_id(5, &d), transfer_id(6, &d));
    }
    #[test]
    fn domains_are_distinct_and_prefix_lengths_are_unambiguous() {
        assert_ne!(
            sha256(&[LEAF_DOMAIN, b"x"].concat()),
            sha256(&[NODE_DOMAIN, b"x"].concat())
        );
        let mut a = vec![];
        put_str(&mut a, "ab").unwrap();
        put_str(&mut a, "c").unwrap();
        let mut b = vec![];
        put_str(&mut b, "a").unwrap();
        put_str(&mut b, "bc").unwrap();
        assert_ne!(a, b);
    }
    #[test]
    fn fixed_manifest_signature_vector_is_stable() {
        let bytes = b"offline-vector-v1";
        let digest = sha256(bytes);
        let id = transfer_id(bytes.len() as u64, &digest);
        let archive = sha256(b"archive");
        let lh = leaf(&id, 0, bytes).unwrap();
        let mut m = TransferManifest {
            version: 1,
            transfer_id: id,
            publisher_id: "publisher-vector".into(),
            package_name: "agent".into(),
            package_version: "1.0".into(),
            package_format_version: 1,
            export_len: bytes.len() as u64,
            export_sha256: hex::encode(digest),
            archive_sha256: hex::encode(archive),
            chunk_size: CHUNK_SIZE as u32,
            chunk_count: 1,
            merkle_root: hex::encode(lh),
            signature: placeholder("publisher-vector"),
        };
        let ph = sha256(&manifest_signing_bytes(&m).unwrap());
        let ts = 123u64;
        let nonce = [0x11; 16];
        let sig=hex::decode("4506e05e7375b50aa4057c94b8b095771a2d7dc1e98f8960372dd1a45d06946ccf47a53557fbf588ee6748fe0d8b762d62923e385e227e8651903315ebd3d907").unwrap();
        m.signature = aip_types::Signature {
            algorithm: aip_types::AlgorithmId::Ed25519,
            signer_id: m.publisher_id.clone(),
            timestamp: ts,
            nonce,
            payload_hash: ph,
            signature_bytes: sig.clone(),
        };
        assert_eq!(
            m.transfer_id,
            "44f2b98dc9b40946bbbb40dc1b9e93df6fdd712b8ca8198bbfac41fb6550f1d6"
        );
        assert_eq!(
            m.export_sha256,
            "22d522c4b60e244375691609b2df43838172322d3260ee5582ae2f212781d6fd"
        );
        assert_eq!(
            m.archive_sha256,
            "0eb3e36bfb24dcd9bb1d1bece1531216b59539a8fde17ee80224af0653c92aa3"
        );
        assert_eq!(
            m.merkle_root,
            "3b1cadd58f5acbdb02a89f5f00452ee5179c30585741dec63564fc0dc21310b4"
        );
        assert_eq!(
            hex::encode(ph),
            "5a0ab373b06a92b462d84e520dd0b7bc95db130e232778094cb4891697477727"
        );
        assert_eq!(hex::encode(&sig),"4506e05e7375b50aa4057c94b8b095771a2d7dc1e98f8960372dd1a45d06946ccf47a53557fbf588ee6748fe0d8b762d62923e385e227e8651903315ebd3d907");
        assert_eq!(hex::encode(manifest_signing_bytes(&m).unwrap()),"4149502d444953545249425554494f4e2d4d414e49464553542d5349474e2d76310000010000004034346632623938646339623430393436626262623430646331623965393364663666646437313262386361383139386262666163343166623635353066316436000000107075626c69736865722d766563746f72000000056167656e7400000003312e300001000000000000001122d522c4b60e244375691609b2df43838172322d3260ee5582ae2f212781d6fd0eb3e36bfb24dcd9bb1d1bece1531216b59539a8fde17ee80224af0653c92aa300040000000000013b1cadd58f5acbdb02a89f5f00452ee5179c30585741dec63564fc0dc21310b4");
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/transfer-v1.json")).unwrap();
        assert_eq!(vector["transfer_id"], m.transfer_id);
        assert_eq!(
            vector["canonical_signing_bytes_hex"],
            hex::encode(manifest_signing_bytes(&m).unwrap())
        );
        assert_eq!(vector["aip_signature_bytes_hex"], hex::encode(&sig));
        assert!(verify_manifest(
            &m,
            "publisher-vector",
            &hex::decode("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12")
                .unwrap()
        )
        .is_ok());
    }

    #[test]
    fn odd_leaf_is_duplicated_and_proof_shape_is_fixed() {
        let chunks = vec![vec![1; CHUNK_SIZE], vec![2; CHUNK_SIZE], vec![3]];
        let total = (CHUNK_SIZE * 2 + 1) as u64;
        let export_bytes: Vec<u8> = chunks.iter().flatten().copied().collect();
        let export_digest = sha256(&export_bytes);
        let id = transfer_id(total, &export_digest);
        let hashes: Vec<_> = chunks
            .iter()
            .enumerate()
            .map(|(i, c)| leaf(&id, i as u32, c).unwrap())
            .collect();
        let levels = tree(&hashes);
        let manifest = TransferManifest {
            version: MANIFEST_VERSION,
            transfer_id: id,
            publisher_id: "publisher".into(),
            package_name: "package".into(),
            package_version: "1".into(),
            package_format_version: 1,
            export_len: total,
            export_sha256: hex::encode(export_digest),
            archive_sha256: hex::encode(sha256(b"archive")),
            chunk_size: CHUNK_SIZE as u32,
            chunk_count: 3,
            merkle_root: hex::encode(levels.last().unwrap()[0]),
            signature: placeholder("publisher"),
        };
        let pieces: Vec<_> = chunks
            .into_iter()
            .enumerate()
            .map(|(i, bytes)| TransferChunk {
                index: i as u32,
                bytes,
                proof: proof(&levels, i),
            })
            .collect();
        assert_eq!(pieces[2].proof[0], hex::encode(hashes[2]));
        assert_eq!(
            manifest.transfer_id,
            "f77c83e31532cc2c73fa3f7080ac8d837a8d430466081cec959fff3d9611bde3"
        );
        assert_eq!(
            manifest.export_sha256,
            "7b4964cc7b82958519231cba2c3951a224c2f9ac386b15aa9b639a98ba4da452"
        );
        assert_eq!(
            manifest.merkle_root,
            "e93cb7a966e518528e85502872ba600233a4bbc1c83c5c73eb9f3d946be0bc27"
        );
        assert_eq!(
            pieces[2].proof,
            vec![
                "7de55d3373d7d21d3436804492676d105b7812986aed0fd5332430d388e734fa",
                "b76369a113cb410d464339513a136ea5b5ff033520a9c6da66e19f65c75ae6ac"
            ]
        );
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/merkle-v1-odd3.json")).unwrap();
        assert_eq!(vector["transfer_id"], manifest.transfer_id);
        assert_eq!(vector["merkle_root"], manifest.merkle_root);
        assert_eq!(
            vector["proof_for_index_2"],
            serde_json::json!(pieces[2].proof)
        );
        for piece in &pieces {
            verify_chunk(&manifest, piece).unwrap();
        }
        let mut bad = pieces[2].clone();
        bad.proof[0] = hex::encode(sha256(b"wrong duplicate"));
        assert!(verify_chunk(&manifest, &bad).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn disk_finalization_rejects_signed_export_digest_mismatch() {
        use aip_crypto::custody::{Custodian, InMemoryCustodian};
        let signer = InMemoryCustodian::generate();
        let export = b"exact bytes with a deliberately false signed digest";
        let false_digest = sha256(b"different bytes");
        let id = transfer_id(export.len() as u64, &false_digest);
        let root = leaf(&id, 0, export).unwrap();
        let mut manifest = TransferManifest {
            version: MANIFEST_VERSION,
            transfer_id: id,
            publisher_id: "publisher".into(),
            package_name: "agent".into(),
            package_version: "1.0.0".into(),
            package_format_version: 1,
            export_len: export.len() as u64,
            export_sha256: hex::encode(false_digest),
            archive_sha256: hex::encode(sha256(b"archive")),
            chunk_size: CHUNK_SIZE as u32,
            chunk_count: 1,
            merkle_root: hex::encode(root),
            signature: placeholder("publisher"),
        };
        manifest.signature = signer
            .sign("publisher", &manifest_signing_bytes(&manifest).unwrap())
            .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "aip-dist-digest-mismatch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut receiver =
            DiskTransferReceiver::create(&dir, manifest, "publisher", signer.public_key()).unwrap();
        receiver
            .accept(TransferChunk {
                index: 0,
                bytes: export.to_vec(),
                proof: vec![],
            })
            .unwrap();
        assert!(receiver
            .finalize("publisher", signer.public_key(), &"00".repeat(32))
            .is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
