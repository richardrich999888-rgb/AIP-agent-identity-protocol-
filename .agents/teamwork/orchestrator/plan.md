# Project Plan: Enterprise Accountability Console (`aip-console`)

## Overview
Build the enterprise web interface for AIP (Agent Identity Protocol) with Syntriass branding, offline 14-rule WASM verification, interactive DAG, tamper simulator, authority builder, and vault explorer.

## Phases
- Phase 0: Survey (3 parallel agents: 2 Explorers + 1 Spec Miner)
  - Map Rust `aip-protocol` rules, `aip-wasm` build setup, `aip-service` endpoints, sample fixtures.
  - Survey frontend architecture requirements (Next.js 15, React 19, Tailwind, shadcn/ui, @xyflow/react).
  - Produce comprehensive feature inventory and technical specs.
- Phase 1: Decomposition & Setup
  - Synthesize findings into `PROJECT.md` with Feature Inventory, Milestones, and Interface Contracts.
  - Launch parallel tracks: Implementation Track & E2E Testing Track.
- Phase 2: Milestone Execution (Sub-orchestrators for milestones)
  - M1: WASM Engine Integration & 14-Rule Verification Ledger (R1)
  - M2: Interactive Accountability Graph DAG (R2)
  - M3: Adversarial Tamper Simulator (R3)
  - M4: Authority Management & Visual Lattice Builder (R4)
  - M5: Evidence Vault Explorer & Offline Mock Fallback (R5)
  - M6: App Shell, Syntriass Enterprise Branding & Navigation (R6)
- Phase 3: Final E2E Test Suite Pass (Tiers 1-4)
- Phase 4: Adversarial Coverage Hardening (Tier 5)
