# AIRI Canonical Byte Encoding — Normative

This is the format a signature covers. The JSON schemas beside it describe
object shape for tooling and are not normative.

## Primitives

| Writer | Bytes |
|---|---|
| `put_u8(v)` | 1 byte |
| `put_u16(v)` | 2 bytes, little-endian |
| `put_u32(v)` | 4 bytes, little-endian |
| `put_u64(v)` | 8 bytes, little-endian |
| `put_bytes(d)` | `put_u32(len(d))` then `d` |
| `put_str(s)` | `put_bytes(utf8(s))` |
| `put_domain(t)` | `put_str(t)` — always first in a signed payload |
| `put_opt_str(s)` | `0x00`, or `0x01` then `put_str(s)` |
| `put_opt_u64(v)` | `0x00`, or `0x01` then `put_u64(v)` |
| `put_opt_digest(d)` | `0x00`, or `0x01` then `put_bytes(d)` |
| `put_opt_bytes16(v)` | `0x00`, or `0x01` then `put_bytes(v)` |

Every variable-length field is length-prefixed and every optional field
carries a presence byte. That is what makes the encoding injective: no two
distinct values share a byte stream, so a signature commits to exactly one
interpretation.

**Fixed-width fields inside `identity_bytes` are appended raw, not
length-prefixed.** Getting this wrong is not theoretical — the first port of
the Python SDK length-prefixed `exe_content_sha256` and the parity vectors
caught it before it shipped.

## Domains

| Tag | Object |
|---|---|
| `SYNTRIASS/AIRI/EVENT/v1` | `AiriEvent` signing preimage |
| `SYNTRIASS/AIRI/PARAM_COMMITMENT/v1` | Parameter, prompt, output, argv commitments |
| `GHOST/ExecutionIdentity/v1` | `ExecutionBinding::identity_bytes` (defined in `aip-types`) |

## Event preimage

```
put_domain("SYNTRIASS/AIRI/EVENT/v1")
put_u16(version)                        // 1
put_str(agent_id)
put_bytes(execution_id)                 // 16
put_opt_bytes16(parent_execution_id)
put_opt_bytes16(decision_id)
put_u64(sequence)
put_bytes(prev_event_hash)              // 32
put_u64(emitted_at_ms)
put_str(framework.name)
put_str(framework.version)
put_str(framework.adapter_version)
runtime_binding: 0x00, or 0x01 then put_bytes(identity_bytes())
put_u8(kind_code)
<payload>
```

### `ExecutionBinding::identity_bytes`

```
put_domain("GHOST/ExecutionIdentity/v1")
put_u16(version)
put_str(agent_id)
<raw> pid                u32 LE, 4 bytes
<raw> pid_start_ticks    u64 LE, 8 bytes
<raw> boot_id            16 bytes
<raw> exe_content_sha256 32 bytes
```

`exe_path` and `bound_at_ms` are excluded: two spellings of the same binary
are one identity, and a same-path different binary is not.

## Kind codes

| Code | Kind |
|---|---|
| `0x01` | `AgentExecutionStarted` |
| `0x02` | `ModelInvocationRequested` |
| `0x03` | `ModelInvocationObserved` |
| `0x04` | `ToolInvocationRequested` |
| `0x05` | `ToolExecutionReported` |
| `0x06` | `SubprocessExecution` |
| `0x07` | `ExecutionCompleted` |
| `0x08` | `ExecutionFailed` |
| `0x09` | `ExecutionContextPropagated` |

## Payload bodies

**AgentStart** — `put_opt_str(agent_role)`, `put_opt_str(framework_run_id)`

**ModelProvenance** — `put_str(model_id)`, `put_opt_digest(model_digest)`,
`put_str(runtime)`, `put_opt_str(runtime_version)`,
`put_opt_str(inference_request_id)`, `put_opt_digest(prompt_commitment)`,
`put_opt_digest(output_commitment)`, `put_opt_str(accelerator)`

**ToolInvocation** — `put_str(tool_id)`, `put_str(action_kind)`,
`put_bytes(parameter_commitment)`, `put_opt_str(tool_call_id)`,
`put_opt_str(target)`

**ToolReport** — `put_str(tool_id)`, `put_bytes(parameter_commitment)`,
`put_u8(outcome)`, `put_opt_digest(result_commitment)`, then transport
status as `0x00` or `0x01` + `put_u64`

**SubprocessReport** — `put_str(program)`, `put_bytes(argv_commitment)`,
then pid as `0x00` or `0x01` + `put_u64`

**Completion** — `put_u8(outcome)`, `put_opt_str(detail)`

**ContextPropagation** — `put_u8(boundary)`, `put_bytes(to_execution_id)`

### Enum codes

`ReportedOutcome`: Success `0x01`, Failure `0x02`, Denied `0x03`,
Indeterminate `0x04`.
`PropagationBoundary`: AsyncTask `0x01`, Thread `0x02`, Process `0x03`,
Subprocess `0x04`, WorkerQueue `0x05`.

## Commitments

```
commit(x) = SHA-256( put_domain("SYNTRIASS/AIRI/PARAM_COMMITMENT/v1") ‖ put_bytes(x) )
```

Domain-separated rather than a bare SHA-256, so a digest computed elsewhere
in the system — a packet hash, an observer head, a Merkle leaf — cannot be
presented as a parameter commitment.

For structured values, serialise deterministically first. The Python SDK uses
`json.dumps(sort_keys=True, separators=(",", ":"))`; any implementation must
match, or two commitments of identical arguments will differ and a verifier
will see a parameter substitution that never happened.

## Signing

```
payload_hash    = SHA-256(preimage)
signature_bytes = Ed25519_sign(agent_private_key, preimage)
```

The signature is over the **preimage**, not over the hash. `signer_id` must
equal the event's `agent_id`.

## NEXORA carriage

An event commits as a Merkle leaf under `LeafKind::AiriEvent` (`0x09`):

```
leaf = merkle_leaf( put_domain("SYNTRIASS/NEXORA/LEAF/v1")
                  ‖ put_u8(0x09) ‖ put_bytes(signing_preimage) )
```

Inside a `NexoraProof` (package version **2**), under `Component::Airi`
(`0x0A`), appended after `Commitment`:

```
put_u8(0x0A)
0x00, or 0x01 then:
  put_str(agent_id)
  put_bytes(agent_public_key)
  put_u32(len(events))
  for each: put_bytes(signing_preimage) ‖ put_signature(signature)
```

The event's own preimage is committed, not a re-serialisation, so a verifier
checks one artefact rather than trusting a round-trip.

## Conformance

An implementation is conformant when it reproduces
`sdk/python/tests/parity_vectors.json` byte for byte and its signatures
verify under `aip-airi/tests/python_interop.rs`. Schema validation
establishes neither.
