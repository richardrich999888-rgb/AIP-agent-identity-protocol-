Independent verification of workflow 40850559136 passed for all three original captures from source `42d0d96c9cc9d3075c792a195cc74e4171b0e817`.

| Capture | Batches / health / kernel events | Whole task has signed Active coverage | Signed reconciliation |
| --- | --- | --- | --- |
| same-run | 34 / 3 / 1011 | Yes | CannotProve / ActionEvidenceUnavailable |
| same-run-interruption | 9 / 3 / 283 | No | CannotProve / WindowNotCovered |
| same-run-recovery | 34 / 4 / 1045 | Yes | CannotProve / ActionEvidenceUnavailable |

The native archive verifier returned zero findings for each original archive pair. Their SHA256 values match both the separately retained parent checkpoint and the parent operator trust checkpoint. The native bundle evaluator used that parent trust and returned exactly the original retained evaluation, without taking trust from the submitted bundle.

Both observed profiles retain identity `Match { observations: 7 }` and temporal `WithinWindow`. Their two process-instance summaries were independently reconstructed from original signed kernel events within the actual task window; the agent process and executable digest match the signed authority binding. Their action remains `Unobservable`, so the result is not a claim of business-action agreement. The nested availability field remains `Unavailable { reason: WindowNotCovered }` exactly as originally signed and evaluated; it is distinct from the top-level reconciliation reason.

The interruption profile retains `NoReference`, temporal `Indeterminate`, no task process bindings, and a coverage endpoint before the task began. Its frozen batch hash is unchanged. The recovery capture has its own public anchor and trust epoch and does not repair the interruption's missing coverage. All profiles retain two model calls and empty cleanup-error lists.

From a clean clone, first build the two native tools with `cargo build --locked -p aip-observe-verify -p aip-mcp-gateway --bin aip-observe-verify --bin aip-execution-assurance`. Then run `python3 -B validation/final_acceptance/same-run-candidate/verification/verify.py`. The default input is the tracked sibling `originals/` directory; no ignored local download is required. The script validates every original byte count and SHA256 in `originals/files.json`, safely decompresses only its explicitly listed gzip files into a temporary directory, and runs native verification against those exact restored bytes and the restored parent trust. The default reproduction passed for all 131 retained originals, including six gzip files, totaling 5,128,015 original bytes. An explicit `--capture-root` override remains available for a retained-manifest or uncompressed capture root.

`commands.json` records the native commands, temporary materialization mode and exit codes; `verification-results.json` records the manifest hash, validated file count, original input hashes, selected capture-source hashes, native binary hashes, exact public result fields and coverage boundaries. Native verification ran locally on Darwin against the retained Linux artifacts. The hashes identify bytes; they do not authenticate artifact-download origin by themselves. Original retained files were not rewritten or shortened, and temporary restored bytes were removed after verification.

Local collector isolation still shares the kernel and root authority. These results do not establish separate administrative custody, logical tool-to-kernel causality, production approval, durable resend, or forward-clock-jump qualification.
