# 2.4 live orphan evidence (native, not P0-059)

Command: `VANIAN_OPA_BIN=… GATE_VENV/bin/python command-center/lab/live_orphan.py OUT`.
Each directory holds `result.json` (checks, calls, lineage, observer summary) and the
inputs: registry (public keys only), lab-issued grants and the operator-signed revocation lists.
The grandchild's TEST private key is deleted at the end of every run; no private key is here.

- `orphan-prefix-hole/` — **the finding**, run before the fix (21 Nov, ~18:35 IST): the orphaned
  grandchild presented `["g-root", "g-worker"]`, leaving out the revoked `g-recon`, and the gate
  returned ALLOW and forwarded it (`calls.stripped_chain`). 13 passed / 3 failed checks.
- `orphan-fixed-1..3/` — after the fix (the gate derives chain and depth from the registry lineage):
  16 passed / 0 failed, 3 of 3 runs.
- `lab-run-20261121T125938Z/` — the same run from `run.sh`: 16/16.
