# Portable AIP package export and offline verification

The `aip-package` binary builds a package using the existing v1 format,
signs it with the existing `Custodian` and `sign_package()` APIs, writes a
portable JSON export, and verifies it offline with
`verify_package_contents()`. Verification does not execute package files and
does not authorize installation or execution.

## Export format

The export JSON has `export_version: 1` and contains:

- `package_format_version` (existing signed package format v1 or v2),
- `publisher_id`,
- the parsed `manifest` metadata,
- `archive_sha256`,
- `archive_base64`, which decodes to the exact ZIP archive bytes, and
- `signature`, the existing detached AIP signature envelope.

The export and nested manifest/signature schemas reject unknown fields. The
publisher public key is not in this export. Provision a separate anchor file
through a trusted channel:

```json
{
  "version": 1,
  "publishers": [
    { "publisher_id": "publisher.example", "public_key_hex": "<64 hex characters>" }
  ]
}
```

Package signature verification uses the publisher key from that file. A key
inside the package cannot establish its own trust. The AIBOM publisher uses a
separate anchor when the sealed-artifact mode is selected.

## Software-only two-machine demonstration

Run from the repository root. The demo publisher uses an ephemeral
`InMemoryCustodian`; it retains no private key. Its generated public anchor
must be authenticated and transferred separately from the package export.
Production publishers should use their configured wrapped-file or hardware
custodian through the existing package APIs.

Publisher machine:

```sh
mkdir -p /tmp/aip-pkg-demo/input/config
printf '{"mode":"offline-demo"}\n' > /tmp/aip-pkg-demo/input/config/runtime.json
cargo run -p aip-package-cli --bin aip-package -- demo-publish \
  --input-dir /tmp/aip-pkg-demo/input \
  --name demo-agent --version 1.2.3 --publisher-id publisher.example \
  --aibom-digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --export /tmp/aip-pkg-demo/evidence-package.json \
  --anchors /tmp/aip-pkg-demo/publisher-anchors.json
```

Verifier machine, after receiving the export and separately authenticating
`publisher-anchors.json`:

```sh
cargo run -p aip-package-cli --bin aip-package -- verify \
  --package /path/to/evidence-package.json \
  --anchors /path/to/publisher-anchors.json \
  --aibom-digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --output-dir /tmp/aip-pkg-verified \
  --accepted-name demo-agent --accepted-publisher publisher.example \
  --minimum-version 1.2.0
```

The verifier creates the output directory only after cryptographic checks and
policy pass. The directory must not already exist. On success it prints JSON
with `status: "VERIFIED"` and the files extracted. Output files are data; the
CLI never launches them.

Tamper demonstration: make a copy with a modified archive and verify it. The
first command exits nonzero; the original export remains usable:

```sh
python3 - <<'PY'
import base64, json
source = '/path/to/evidence-package.json'
tampered = '/tmp/aip-pkg-demo/tampered-package.json'
value = json.load(open(source, encoding='utf-8'))
archive = bytearray(base64.b64decode(value['archive_base64']))
archive[20] ^= 1
value['archive_base64'] = base64.b64encode(archive).decode('ascii')
with open(tampered, 'x', encoding='utf-8') as f:
    json.dump(value, f)
PY
cargo run -p aip-package-cli --bin aip-package -- verify \
  --package /tmp/aip-pkg-demo/tampered-package.json \
  --anchors /path/to/publisher-anchors.json \
  --aibom-digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --output-dir /tmp/aip-pkg-tampered-output
# This must fail; /tmp/aip-pkg-tampered-output is not created.
cargo run -p aip-package-cli --bin aip-package -- verify \
  --package /path/to/evidence-package.json \
  --anchors /path/to/publisher-anchors.json \
  --aibom-digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --output-dir /tmp/aip-pkg-verified-original
```

Use fresh paths for the export, anchors and extraction directory; publishing
uses exclusive file creation and extraction refuses an existing output dir.

## AIBOM binding

The package always compares its signed AIBOM digest to an external input. For
an independently verified AIBOM, provide its manifest, detached seal, and
separately provisioned AIBOM publisher anchor instead of `--aibom-digest`:

```sh
cargo run -p aip-package-cli --bin aip-package -- verify \
  --package /path/to/evidence-package.json \
  --anchors /path/to/package-publisher-anchors.json \
  --aibom-manifest /path/to/aibom-manifest.json \
  --aibom-seal /path/to/aibom-seal.json \
  --aibom-anchor /path/to/aibom-publisher-anchor.json \
  --output-dir /tmp/aip-pkg-verified
```

The AIBOM manifest is parsed and validated by `aip-aibom`; its canonical
digest is derived by `canonical::manifest_digest_hex`; `verify_seal()` checks
the detached seal against the separate AIBOM publisher key. Only then is that
digest supplied to the existing package verifier. The AIBOM anchor file has
`publisher_id` and `public_key_hex` fields and is not taken from either the
package or the AIBOM manifest.

Alternatively, `--aibom-digest` accepts an externally supplied 32-byte SHA-256
hex digest. In that mode the tool proves only that the package binds that
digest; authenticity of the AIBOM represented by it is outside this command.

## Release policy and limits

Optional verifier arguments include `--accepted-name`, `--accepted-publisher`,
`--minimum-version`, repeatable `--revoked-publisher`, and repeatable
`--revoked-release publisher/name@MAJOR.MINOR.PATCH`. Version ordering is
defined only for exactly three decimal numeric components. Leading zeroes,
pre-release/build suffixes, and other version shapes are rejected when a
minimum is requested. Without policy flags, a valid signature establishes
authenticity/integrity only, not freshness or approval. Revocations are local
operator-supplied CLI policy; this tool does not fetch a revocation service.

The offline verifier applies the package crate's archive, entry, manifest,
per-file, and aggregate uncompressed-size limits and verifies the complete
archive inventory. A signature does not prove package contents are safe, and
verification does not authorize installation or execution. The demo uses a
synthetic AIBOM digest unless replaced with a real independently verified
manifest digest; the repeated `a` value above is only a format-valid example.


The CLI target lives in the higher-level ip-package-cli workspace crate so the ip-package library does not depend on the AIBOM product. The command name and subcommands are unchanged.
