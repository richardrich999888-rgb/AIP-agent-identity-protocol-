Independent verification of genuine workflow **40854983596**, captured from `9ed1662af95ce83bbbee69c9387d5bd638713575`, passes for the original three profiles. These are functional and cryptographic verification results; **probe-to-collector key inaccessibility is NOT_MET / BLOCKED, and separate administrative custody is BLOCKED** in the shared-root local topology.

| Profile | Batches / health / kernel events | Whole task has one signed Active epoch | Reconciliation | Bound process instances |
| --- | --- | --- | --- | --- |
| same-run | 37 / 4 / 1046 | Yes | CannotProve / ActionEvidenceUnavailable | 2 |
| same-run-interruption | 11 / 3 / 311 | No | CannotProve / WindowNotCovered | 0 |
| same-run-recovery | 35 / 4 / 1062 | Yes | CannotProve / ActionEvidenceUnavailable | 2 |

The actual native offline archive verifier returns zero findings for all three original archive pairs. Original archive hashes match both the separately retained parent checkpoints and parent operator trust. The native evaluator, using that parent trust instead of bundle-supplied trust, exactly reproduces each original evaluation. All three retain verified authority, gateway receipt and signed reconciliation, an authorized `Forwarded` receipt and tool-boundary `Agrees`.

Observed and fresh-recovery profiles have identity `Match { observations: 7 }`, temporal `WithinWindow`, and signed coverage enclosing their complete actual task windows. Their process summaries were reconstructed directly from original signed kernel events; the agent instance and executable digest match the original authority binding. Business action remains `Unobservable`, so both retain `CannotProve / ActionEvidenceUnavailable`. Their nested availability field remains `Unavailable { reason: WindowNotCovered }` exactly as evaluated, distinct from the top-level reconciliation reason.

The interruption profile has `NoReference`, temporal `Indeterminate`, no process bindings in the task window, and a final signed coverage endpoint before its task begins. Its frozen batch hash is unchanged. Recovery has a fresh anchor and trust epoch and does not backfill the interrupted task.

All three public client reports match their exact bundle digest and independently reproduced evaluation. All ten recorded interface statuses pass: API admission, exact bundle retrieval, OpenAPI, Python SDK, compiled TypeScript SDK, official MCP client, cross-tenant refusal, reader write/raw refusal, console browser and signed verdict retrieval. Each client-progress record reaches `COMPLETE / PASS`; each run retains two actual model calls and an empty cleanup-error list.

The separate native console route regression passes **1 test, 0 failed, 0 ignored** and verifies required CSP headers, public shell content and authenticated data routes. See `console-csp-check.json` and its exact log. The Linux artifacts retain console functional PASS and screenshots; they do not retain an independent raw HTTP CSP header capture.

Reproduce from tracked originals without the ignored download directory:

```sh
cargo build --locked -p aip-observe-verify -p aip-mcp-gateway --bin aip-observe-verify --bin aip-execution-assurance
python3 -B validation/final_acceptance/same-run-qualified/verification/verify.py
```

The script validates all **131** entries of sibling `originals/files.json` and materializes its six declared deterministic gzip files into temporary storage, preserving **5,276,580** original bytes. It validates original sizes/hashes before running the native tools, uses separately retained parent trust, and removes the temporary restored tree afterward. `--capture-root` may explicitly select another retained-manifest or uncompressed capture root. `commands.json` and `verification-results.json` retain commands, exits, manifest/input/source/script/native-binary hashes, task and signed coverage boundaries, client statuses and the explicit blocked custody gate. Original retained files were not rewritten or shortened.

The coordinating agent supplied artifact ID `12888619380`, ZIP size `1223840`, and ZIP SHA256 `2fdbaca4bc39acc5580e2ce7a497aa31f49c5e254ec40a597225b67e55b87c3c`; this independent pass verifies retained original bytes and signatures, rather than independently repeating the artifact download. Checksums identify bytes and do not authenticate origin by themselves.

The probe and collector are both launched as UID0 in this local profile; the agent's file-read denials do not establish collector-key inaccessibility to the probe. See `../../infrastructure/probe-key-boundary.md`. These results do not qualify separate administrative custody, host-compromise resistance, logical tool-to-kernel causality, production approval, durable resend or forward-clock-jump handling.
