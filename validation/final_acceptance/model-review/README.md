# Reviewed local model artifacts

Decision: retain the existing Ollama 0.40.11 runtime and `llama3.2:1b` model
pins. No current upstream change to configuration, layers or weights was found.
The failure in Actions run 40740307858 attempt 2 was a local manifest-layout
error, not evidence of a changed model tag. Its primary job log was read at
job ID 123008593400; the relevant traceback is retained in `failed-job-excerpt.log`.

The original upstream manifest is exactly 860 bytes with SHA-256
`baf6a787fdffd633537aa2eb51cfd54cb93ff08e28040095462bb63daf552878`.
`llama3.2-1b.manifest.json` preserves those exact bytes, including the absence of
a final newline. Do not reformat this artifact. The genuine 485-byte config
fixture also preserves its original bytes and hash. Neither fixture contains
weights, private keys or credentials.

## Primary-source comparison

The official tag endpoints on `registry.ollama.ai` and `ollama.com`, queried
with the pinned runtime's exact Accept header, both still return the approved
860-byte manifest and media type. The original manifest is also retrievable
by immutable digest through this actual supported endpoint:

https://registry.ollama.ai/v2/library/llama3.2/blobs/sha256:baf6a787fdffd633537aa2eb51cfd54cb93ff08e28040095462bb63daf552878

Both hosts' `/manifests/sha256:...` routes returned 404 `MANIFEST_UNKNOWN`.
Therefore the bootstrap uses the proven immutable **blob** route for a bounded
metadata preflight; it does not invent digest-qualified `ollama pull` CLI
semantics. The CLI still populates its supported model-name layout, after which
the selected original manifest and every config/layer undergo full size/hash
verification. A changed tag cannot bypass those checks.

The blob endpoint omitted a response Content-Type; its approved document bytes
still declare the exact Docker v2 manifest media type. The tag endpoints return
that Content-Type. Length, digest, schema and document media type are all
validated. `review.json` records the exact URLs, hashes, sizes and scope.

The runtime tag resolves to upstream commit
`675150d6ad2747df1e218ef59de9194bc4a7e538`. Its source explains the layout:

- [manifest storage and legacy GC anchor](https://github.com/ollama/ollama/blob/675150d6ad2747df1e218ef59de9194bc4a7e538/manifest/manifest.go#L1096-L1201): the original bytes are stored as a content-addressed blob and linked by the v2 name; a separate legacy anchor appends the original manifest itself as a layer for downgrade garbage collection.
- [pull storage and downgrade anchor call](https://github.com/ollama/ollama/blob/675150d6ad2747df1e218ef59de9194bc4a7e538/server/images.go#L1294-L1303).
- [downgrade anchor construction](https://github.com/ollama/ollama/blob/675150d6ad2747df1e218ef59de9194bc4a7e538/server/images.go#L1536-L1547).
- [runtime Accept header and exact raw response handling](https://github.com/ollama/ollama/blob/675150d6ad2747df1e218ef59de9194bc4a7e538/server/images.go#L1629-L1648).
- [v2 host/path conventions](https://github.com/ollama/ollama/blob/675150d6ad2747df1e218ef59de9194bc4a7e538/manifest/paths.go#L22-L28).

The actual hosted layout retained from run 40745805805 has a 1023-byte legacy
anchor with SHA-256
`728ac54eed40c4c447b407828c1f1c633033657245fe8fd42931efc7eab30743`.
Its extra layer refers to the original 860-byte manifest. Its v2 name resolves
to `blobs/sha256-baf6...`, preserving the original approved bytes. Commit
`e2cd2d6` already fixed selection of that original path; this recovery preserves
the fix and adds the immutable preflight and regression coverage.

The official release API independently reports the existing Linux x86_64
archive pin: 1,508,659,610 bytes, SHA-256
`7bedab90dd122661be78798e9f0edf37fccf0cccf2699d2c58ea1a3afdc04b6d`.
The archive was not re-downloaded during this review. All five genuine existing
local config/layer files were rehashed and size-checked, including the
1,321,082,688-byte GGUF weights. All match the unchanged approved manifest.
Remote weights were checked with HEAD only; no new weights or cloud inference
were requested.

## Executed validation and limits

```bash
python3.12 -m unittest discover -s validation/enterprise -p same_run_controls_test.py -v
```

Ten portable controls passed, including exact-artifact acceptance, original-v2
selection despite the rewritten legacy GC anchor, changed v2 bytes at the
correct blob path, unreviewed references, and config size/hash tampering. The
config tests use the authentic small config artifact; they do not substitute
fake weights. Metadata-only validation explicitly fails full model verification
when the required blobs are absent.

The new `fetch_reviewed_manifest()` was actually run against the immutable
official source, returning exactly the approved 860 bytes. The new full
`verify_model()` was actually run read-only against the existing local cache;
all five complete blob hashes and sizes passed. `local-check.json` records
those results. These are metadata/cache integrity checks on Darwin, not fresh
Linux installation, inference, agent execution or kernel evidence.

The earlier hosted run 40745805805 passed the exact runtime/model provisioning
gate, then failed before the autonomous workload because the isolated model UID
could not traverse the runtime path. Commit `3f025d2` adds public-asset
permissions while keeping bootstrap HOME/logs private; that change and its
privacy regression are preserved. The combined branch still requires a fresh
runner-executed same-run workflow before that acceptance gate can pass.
