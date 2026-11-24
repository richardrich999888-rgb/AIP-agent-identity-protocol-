# Retained public evidence for source 32619a1

Implementation source: `32619a16b102d14d9cca667699a3b64394ca644f`.
These are original GitHub Actions public artifacts, retained without rewriting
the signed archives. Both ZIP digests matched GitHub's artifact metadata.

| Artifact | Workflow run | Artifact ID | SHA-256 |
| --- | --- | --- | --- |
| `rbi-public.zip` | 44916522539 | 14711873252 | `e7dbd38cc1fdecf211556147d593d3159f7313416a1549ee7a62f0e65d1e822f` |
| `genuine-agent-public.zip` | 44916522554 | 14711609978 | `f0c35f0d2ef1239f0615f0b95d0128b778ca1cdab6a56d25a650e9f8d9b2c75e` |

The rehearsal is a controlled kernel workload. The genuine-agent artifact
contains normal AI execution, observer interruption and fresh recovery; the
controller reports two model calls in each profile. No model or API credential
was required for offline verification.

The corresponding `*-offline-local.json` receipts record a separate local
execution of the current `aip-observe-verify` binary, with networking disabled
by the policy `(version 1) (allow default) (deny network*)`. A socket attempt
was refused with EPERM inside each verification process before the verifier
was invoked. Original archive hashes were checked against the retained export
manifest or controller checkpoints. A temporary copy with a middle record
deleted was rejected with exit code 1 in every case; originals were unchanged.

Normal execution: 47 batches/4 health records. Observer interruption: 18/3.
Recovery: 46/4. All archive checks reported zero findings. The interrupted
profile still reports `UNAVAILABLE_OBSERVER_INTERRUPTED`: integrity of its
preexisting archive does not prove the work performed after observation stopped.
The rehearsal independently verified 85 batches/4 health records.

These are hosted validation results under a single GitHub administration.
Public anchors and checkpoints came from that administration. Independent
verifier execution does not establish independent collector administration,
customer-approved installation or a signed proof of model/business semantics.
Neither archive tests per-agent filtered retention across a collector outage.
That scoped pilot qualification remains an explicit acceptance gate.

The genuine ZIP includes each profile's `observer-anchor.json` and
`checkpoint.json` beside `public/attested.archive.jsonl` and
`public/health.archive.jsonl`. The rehearsal public key and archives are in
`rbi-rehearsal/system/work/state/`, with exact file digests in
`export-manifest.json`. Customer verification must use independently approved
public trust and separately retained checkpoints, not adopt an unknown sender's
key merely because its archive verifies against that key.
