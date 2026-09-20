# Manifest — OrbitalTrust Accountability Layer

Source commit: `af2f4d965eb13aae89b96e6a10f72ff671de969a`  
Files: **114**  ·  Lines: **35,440**  ·  Bytes: **1,370,331**

Every file in this archive, with a SHA-256 so the recipient can verify
nothing changed in transit. Reproduce with:

```sh
find . -type f ! -name MANIFEST.md ! -name README.md -exec sha256sum {} + | sort -k2
```

| File | Lines | SHA-256 |
|---|---:|---|
| `docs/ACCOUNTABILITY_PRODUCT_LINE.md` | 94 | `a833e28f1bafc3a5…` |
| `docs/IDF-TYPESTATE-AUTHORIZATION.md` | 516 | `62c7b69c3e0d35ce…` |
| `python-sdk/.gitignore` | 2 | `862263fa1f46c20f…` |
| `python-sdk/README.md` | 76 | `1118de6601dffc12…` |
| `python-sdk/pyproject.toml` | 13 | `c5858b810f5a6015…` |
| `python-sdk/otgovern/__init__.py` | 436 | `c948980ff9b7491b…` |
| `python-sdk/otgovern/selftest.py` | 64 | `9a4b82527f62fdb4…` |
| `python-sdk/tests/test_otgovern.py` | 120 | `468ae914e5895150…` |
| `rust/workspace-Cargo.toml` | 148 | `235e2122bead9b57…` |
| `rust/ot-accountability-core/Cargo.toml` | 27 | `7fc943791a237b18…` |
| `rust/ot-accountability-core/src/aip.rs` | 1629 | `3d890215b486f137…` |
| `rust/ot-accountability-core/src/authority.rs` | 562 | `e98d3bf5ed5fa557…` |
| `rust/ot-accountability-core/src/authority_journal.rs` | 794 | `f6e3e3aad56f86ce…` |
| `rust/ot-accountability-core/src/chain.rs` | 131 | `90e1f1a471cfba79…` |
| `rust/ot-accountability-core/src/identity.rs` | 577 | `69ee7471e2a0ced7…` |
| `rust/ot-accountability-core/src/lib.rs` | 89 | `b13d2bbe6d91df3f…` |
| `rust/ot-accountability-core/src/lifecycle.rs` | 427 | `a3ffd23db7592d7b…` |
| `rust/ot-accountability-core/src/merkle.rs` | 87 | `3d41618969fced43…` |
| `rust/ot-accountability-core/src/stream.rs` | 286 | `817bc7669e33fcd4…` |
| `rust/ot-accountability-core/src/wasm.rs` | 91 | `1e054be85fc1af3f…` |
| `rust/ot-api-governance/governance.rs` | 394 | `ef20ddeddd24a63c…` |
| `rust/ot-mcp-gateway/Cargo.toml` | 56 | `637d454338f21252…` |
| `rust/ot-mcp-gateway/src/config.rs` | 435 | `99e56c100e9970c0…` |
| `rust/ot-mcp-gateway/src/gateway.rs` | 769 | `b0c55a6953009e2d…` |
| `rust/ot-mcp-gateway/src/http.rs` | 664 | `d6bc9a3b9cc3bcea…` |
| `rust/ot-mcp-gateway/src/identity.rs` | 666 | `663a4a45d3edc911…` |
| `rust/ot-mcp-gateway/src/keyring.rs` | 252 | `a0f10a50ee0610ec…` |
| `rust/ot-mcp-gateway/src/lib.rs` | 128 | `e7c818dc6a27a7fe…` |
| `rust/ot-mcp-gateway/src/main.rs` | 250 | `46eabdd49da156c6…` |
| `rust/ot-mcp-gateway/src/pem.rs` | 89 | `ffefddccc57ce185…` |
| `rust/ot-mcp-gateway/src/protocol.rs` | 340 | `f3af4ca094ff1bdd…` |
| `rust/ot-mcp-gateway/src/provision.rs` | 343 | `23a5ba08236c431b…` |
| `rust/ot-mcp-gateway/src/session.rs` | 268 | `d1bad48265962186…` |
| `rust/ot-mcp-gateway/src/sink.rs` | 190 | `605e5ce6e1bbb64e…` |
| `rust/ot-mcp-gateway/src/trust.rs` | 549 | `46e8824293800fb1…` |
| `rust/ot-mcp-gateway/src/upstream.rs` | 182 | `8ec174b85cc53606…` |
| `rust/ot-mcp-gateway/src/bin/ot-mcp-gateway-http.rs` | 223 | `8774fe860d9b8493…` |
| `rust/ot-mcp-gateway/src/bin/ot-provision.rs` | 201 | `c37bec79ba99611a…` |
| `rust/ot-mcp-gateway/tests/governed_proxy.rs` | 1048 | `260c0ffcc3d50236…` |
| `rust/ot-sentinel/Cargo.toml` | 19 | `2f445db58767ecc5…` |
| `rust/ot-sentinel/src/attestation.rs` | 178 | `8f5626909f1a438d…` |
| `rust/ot-sentinel/src/conformance.rs` | 191 | `66efc29c61685f89…` |
| `rust/ot-sentinel/src/detector.rs` | 1128 | `975a9f6f5b164fbb…` |
| `rust/ot-sentinel/src/finding.rs` | 320 | `3d4a2fec77a4c41e…` |
| `rust/ot-sentinel/src/lib.rs` | 193 | `dd1db207c4ff7d04…` |
| `rust/ot-sentinel/src/observation.rs` | 336 | `8c9e198a5d30698b…` |
| `rust/ot-sentinel/src/patrol.rs` | 474 | `9cc48f8f18437ddf…` |
| `rust/ot-sentinel/src/reconcile.rs` | 507 | `6cd65fb09c94e8b1…` |
| `rust/ot-sentinel/src/registry.rs` | 285 | `e0a118029cdf7f1a…` |
| `rust/ot-sentinel/src/response.rs` | 325 | `431f5caf24a81944…` |
| `rust/ot-sentinel/src/runtime.rs` | 523 | `dfbe39fbcee2cb94…` |
| `rust/ot-sentinel/src/sensors.rs` | 1020 | `bf4fb8ce73079a62…` |
| `rust/ot-sentinel/src/state.rs` | 537 | `86c1215e3af3d96e…` |
| `rust/ot-sentinel/src/time.rs` | 164 | `d2b07216b45c74c9…` |
| `rust/ot-sentinel/src/bin/sentinel.rs` | 194 | `cf704bf8b2bfd5d6…` |
| `rust/ot-sentinel/tests/ghost_hunt.rs` | 1619 | `a7ff3bc4b6171b9a…` |
| `rust/ot-verifier/Cargo.toml` | 16 | `6015af50a174a579…` |
| `rust/ot-verifier/src/lib.rs` | 20 | `5e0523ab65744764…` |
| `rust/ot-verifier/src/main.rs` | 197 | `4cdd77fe7fc0f2ba…` |
| `rust/ot-verifier/src/report.rs` | 101 | `1eed3ba95dd6563b…` |
| `rust/ot-verifier/src/verify.rs` | 435 | `3bc67f53aafe8d8f…` |
| `rust/ot-verifier/tests/python_sdk.rs` | 77 | `6d84496049c62788…` |
| `rust/ot-verifier/tests/verify_dossier.rs` | 248 | `e2c27e81192b443c…` |
| `rust/ot-verifier/tests/fixtures/multisig-mission-dossier.json` | 203 | `70cc55963cb88014…` |
| `rust/ot-verifier/tests/fixtures/post-revocation-execution.json` | 246 | `b4892d0ae5940fb6…` |
| `rust/ot-verifier/tests/fixtures/valid-mission-dossier.json` | 502 | `ab2f9528cab8c474…` |
| `typescript/src/agent/capabilities.ts` | 142 | `9824f087480105ad…` |
| `typescript/src/agent/context.ts` | 62 | `414ed979769b7b0d…` |
| `typescript/src/agent/governed-dispatch.ts` | 330 | `c1e2d1597663f3d6…` |
| `typescript/src/agent/liveCapabilities.ts` | 365 | `8b7ee34018819200…` |
| `typescript/src/agent/tactical-tools.test.ts` | 173 | `2e25e05ef0dc4d83…` |
| `typescript/src/agent/tactical-tools.ts` | 328 | `c3c3a65f83f4b059…` |
| `typescript/src/agent/voice-copilot.ts` | 669 | `190d6b9aa96e181c…` |
| `typescript/src/governance/compliance-schema.ts` | 242 | `9a64493e7ea1e5b6…` |
| `typescript/src/governance/execute-governed.ts` | 90 | `b9c2ea41ff60212b…` |
| `typescript/src/governance/verification-runner.ts` | 93 | `fdb122228443d885…` |
| `typescript/src/governance/wasm/index.ts` | 189 | `58e5f217c03c5531…` |
| `typescript/src/telemetry/crypto.ts` | 126 | `16ad7724828a034f…` |
| `typescript/src/telemetry/governance.ts` | 129 | `3e9a3f79beb02583…` |
| `typescript/src/telemetry/pqc-audit.ts` | 288 | `a4585d90ec7e95a0…` |
| `typescript/src/telemetry/agent-accountability/accountability-service.ts` | 280 | `1838bfaa5cf33f24…` |
| `typescript/src/telemetry/agent-accountability/exporter.ts` | 249 | `7dae8a939cf015af…` |
| `typescript/src/telemetry/agent-accountability/governed-execution.ts` | 323 | `64e562cc01498455…` |
| `typescript/src/telemetry/agent-accountability/ledger-storage.ts` | 116 | `98e6f561785ad5a3…` |
| `typescript/src/telemetry/agent-accountability/types.ts` | 68 | `001067b1a9a31bea…` |
| `typescript/src/telemetry/agent-accountability/verifier.ts` | 169 | `3381c8473c82eac5…` |
| `typescript/src/telemetry/agent-identity/agent-profile.ts` | 172 | `72f9dc014b17b9a8…` |
| `typescript/src/telemetry/agent-identity/identity-registry.ts` | 297 | `46cae60614ff0d80…` |
| `typescript/src/telemetry/agent-identity/identity-store.ts` | 254 | `4685b838b7e3d7dd…` |
| `typescript/src/telemetry/agent-identity/permission-guard.ts` | 210 | `ae002558212080f4…` |
| `typescript/src/telemetry/agent-identity/persistent-identity.ts` | 211 | `ad7c7d87fffc06c1…` |
| `typescript/src/telemetry/nexora/aip-evidence.ts` | 265 | `8d866b67b19e6e8d…` |
| `typescript/src/telemetry/nexora/anchor-chain.ts` | 157 | `e1378d7bfcaaca9b…` |
| `typescript/src/telemetry/nexora/delegation-graph.ts` | 276 | `ef7db9f383688ac2…` |
| `typescript/src/telemetry/nexora/nexora-store.ts` | 193 | `a551169a7deb3752…` |
| `typescript/src/telemetry/nexora/nexora-verifier.ts` | 204 | `2365322da796ac6e…` |
| `typescript/src/telemetry/nexora/types.ts` | 143 | `c9c5266f18dcc991…` |
| `typescript/src/ui/AccountabilityConsole.tsx` | 46 | `fd680184d13bdea7…` |
| `typescript/src/ui/AgentAccountabilityTab.tsx` | 594 | `d27c5708fe7628e1…` |
| `typescript/src/ui/AgentActionFeedHUD.tsx` | 342 | `9d19d4b61003fdfa…` |
| `typescript/src/ui/AgentBadgeHUD.tsx` | 204 | `6a02674b6d301fae…` |
| `typescript/src/ui/JarvisInterface.tsx` | 492 | `bbe30fef86e0fe51…` |
| `typescript/src/ui/PqcInspectorModal.tsx` | 400 | `22a27f0c52fe8b21…` |
| `typescript/tests/action-exporter-ui.test.ts` | 240 | `923ef01b926700f1…` |
| `typescript/tests/agent-identity-accountability.test.ts` | 498 | `5af03d7e793ec8c1…` |
| `typescript/tests/compliance-mapper.test.ts` | 188 | `658f83a5d530459a…` |
| `typescript/tests/copilot-turn.test.ts` | 252 | `e0ebbed4676d99e2…` |
| `typescript/tests/governed-dispatch.test.ts` | 255 | `9f5d5f794c4baff8…` |
| `typescript/tests/hybrid-verification.test.ts` | 204 | `75f29dfbe1d07bfe…` |
| `typescript/tests/nexora-lifecycle.test.ts` | 436 | `ad49305b7b2ab0cf…` |
| `typescript/tests/nexora-live-wiring.test.ts` | 214 | `604555e90dc6370c…` |
| `typescript/tests/persistent-identity.test.ts` | 358 | `886683df7907be81…` |
| `typescript/tests/pqc-inspector.test.ts` | 195 | `68dbea3f4ff50720…` |
| `typescript/tests/qa-verification-suite.test.ts` | 435 | `1649d0bbcbfaaaea…` |
