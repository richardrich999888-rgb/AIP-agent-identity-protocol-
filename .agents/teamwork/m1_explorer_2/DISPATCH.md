## 2026-11-02T08:51:00Z
You are Milestone 1 Explorer 2 (M1 WASM API & Exports Specialist) for Milestone 1: `aip-wasm` Core Engine & Fixtures Pipeline.
Your working directory is: c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\m1_explorer_2\
You MUST read:
- ORIGINAL_REQUEST.md at: c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\ORIGINAL_REQUEST.md
- PROJECT.md at: c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\PROJECT.md
- Survey findings at: c:\Users\shrey\Desktop\Internship\Sniffer Dog\AIP-agent-identity-protocol-\.agents\teamwork\survey_explorer_rust\analysis.md

Your mission:
1. Design and specify the exact Rust code implementation for `aip-standalone/aip-wasm/src/lib.rs`:
   - The 10 exported wasm-bindgen functions matching the Interface Contract in PROJECT.md:
     - `verify_evidence_packet`
     - `verify_bundle_zip`
     - `get_accountability_graph`
     - `recompute_packet_hash`
     - `get_canonical_bytes_hex`
     - `check_scope_permits`
     - `meet_capability_scopes`
     - `extract_bundle_files`
     - `generate_keypair`
     - `get_sample_packet`
   - Detailed error handling, string conversions, JSON serialization, and memory safety.
   - Compatibility with `VerificationContext` (trusted issuers, counterparties, revoked JTIs).
2. Formulate a precise, actionable implementation plan for the Worker.
3. Update `progress.md`, write your `analysis.md` and `handoff.md` in your working directory, and notify the orchestrator (conversation ID: 675111aa-04e8-493f-9811-dbfc1935a77b).
