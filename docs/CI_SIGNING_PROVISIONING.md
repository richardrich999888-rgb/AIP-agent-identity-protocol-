# CI Signing Provisioning

Use this when the repository is private and GitHub build-provenance
attestations are unavailable. The workflows already skip cleanly without the
secret, but adding it causes AIP and AEGIS CI to publish detached GPG
signatures for their checksum manifests.

## Required Secret

Create a GitHub Actions repository secret named:

```text
CI_GPG_PRIVATE_KEY_B64
```

## Export Command

Run this on the machine that holds the AIRON CI signing key:

```bash
gpg --export-secret-keys --armor "airon-ci-signer" | base64 | pbcopy
```

Paste the clipboard value into the GitHub secret. If the local system does not
have `pbcopy`, write the base64 output to a secure temporary file and delete it
after provisioning the secret.

## CI Output

After the secret is configured:

| Workflow | Signed Manifest | Signature Artifact |
| --- | --- | --- |
| AIP Validation | `aip_validation_bundle.sha256` | `aip-validation-bundle-signature` |
| AEGIS lab validation | `validation_bundle.sha256` | `aegis-validation-bundle-signature` |
| AEGIS eBPF bytecode build | `ebpf_bytecode_bundle.sha256` | `aegis-ebpf-bytecode-signature` |

The signature files use GPG armored detached signatures with the `.asc`
extension.

## Verification Pattern

Download the matching manifest and signature artifact, import the public CI
signing key, then verify:

```bash
gpg --verify aip_validation_bundle.sha256.asc aip_validation_bundle.sha256
```

Repeat the same pattern for the AEGIS validation and eBPF bytecode manifests.
