# WASM Bridge Provider & Ingestion Architecture Analysis

**Author**: Milestone 2 Explorer 2 (WASM Bridge Provider & Ingestion Specialist)  
**Date**: 2026-11-02  
**Target Project**: `aip-console` (Next.js 15, React 19, TypeScript, Tailwind CSS, shadcn/ui)  
**Working Directory**: `.agents/teamwork/m2_explorer_2/`

---

## 1. Executive Summary

This document provides the exhaustive architectural design and implementation blueprints for the **AIP WebAssembly Bridge Provider** (`src/lib/wasm/`) and the **Drag-and-Drop Ingestion Component** (`src/components/ingestion/Dropzone.tsx`).

### Core Architectural Guarantees
1. **Zero Verification Logic in JavaScript/TypeScript**:
   All 14 engine verification checks, Trust Floor derivation, tamper detection flags, bundle integrity checks, and accountability DAG reconstructions are executed strictly within the Rust WebAssembly engine (`aip-wasm` compiled from `aip-protocol`). The TypeScript layer acts purely as a typed serialization and orchestration bridge.
2. **Zero SSR Hydration Collisions**:
   Next.js 15 App Router performs server prerendering for all routes. Attempting to instantiate WebAssembly or fetch relative WASM assets on Node.js causes server crashes or React hydration mismatches. The `AipVerifierProvider` utilizes `'use client'` combined with dynamic browser-only module importation (`await import(/* webpackIgnore: true */ '/wasm/aip_wasm.js')`), ensuring clean hydration, robust error boundaries, and non-blocking asynchronous startup.
3. **Dual Compatibility with `PROJECT.md` & Engine Norms**:
   The WASM module and TypeScript types support both standard protocol keys and `PROJECT.md` contract keys (e.g. `overall_valid` & `valid`, `derived_trust_floor` & `trust_floor`, `tamper_evidence` & `tampered`).
4. **Complete 10-Fixture Quick Ingestion Suite**:
   Built-in quick select supports all 10 pre-compiled fixtures in `public/fixtures/` (Valid, Adversarial, Revocation, and Audit ZIP bundles), utilizing compile-time embedded strings in WASM (`get_sample_packet`) for offline instant loading and browser fetch for binary ZIP archives.

---

## 2. Directory Layout & Module Responsibilities

```
aip-console/
├── public/
│   ├── wasm/
│   │   ├── aip_wasm.d.ts           # wasm-pack TypeScript declarations
│   │   ├── aip_wasm.js             # wasm-bindgen JS runtime glue
│   │   ├── aip_wasm_bg.wasm        # 788 KB compiled WebAssembly binary
│   │   └── package.json            # ES module metadata
│   └── fixtures/
│       ├── index.json              # Catalog of all 10 test fixtures
│       ├── honest_counterparty.json & .context.json
│       ├── authority_bound.json & .context.json
│       ├── agent_signed.json & .context.json
│       ├── tampered_summary.json
│       ├── tampered_hash.json
│       ├── tampered_signature.json
│       ├── scope_escalation.json
│       ├── revoked_token.json & .context.json
│       ├── audit_bundle_valid.zip
│       └── audit_bundle_tampered.zip
└── src/
    ├── lib/
    │   └── wasm/
    │       ├── types.ts            # Normative TypeScript interfaces
    │       ├── useAipVerifier.tsx  # React Hook & Context Provider
    │       ├── fixtures.ts         # Fixture catalog and loader utilities
    │       └── EvidenceContext.tsx # Shared evidence session state
    └── components/
        └── ingestion/
            ├── Dropzone.tsx        # Drag-and-drop file ingestion & sample loader
            ├── FixtureModal.tsx    # 10-fixture quick-selection modal
            ├── VerificationLedger.tsx # Owned by Explorer 3
            ├── TrustFloorBadge.tsx    # Owned by Explorer 3
            └── TrustAnchorConfig.tsx  # Owned by Explorer 3
```

---

## 3. WebAssembly Bridge Contract Specification

### 3.1 WASM Exports vs Client-Side Wrapper Signatures

| WASM Rust Export (`aip_wasm.js`) | Client-Side Bridge Function (`useAipVerifier`) | Input Arguments | Output Type | Description |
|---|---|---|---|---|
| `verify_evidence_packet` | `verifyPacket` | `packetJson: string, contextJson?: string` | `VerificationReport` | Evaluates all 14 engine verification rules. Parses JSON output into typed report. |
| `verify_bundle_zip` | `verifyBundleZip` | `zipBytes: Uint8Array, contextJson?: string` | `BundleVerificationResult` | Verifies audit ZIP bundle (manifest, checksums, signature, integrity). |
| `get_accountability_graph` | `getAccountabilityGraph` | `packetJson: string, reportJson?: string` | `AccountabilityGraph` | Constructs React Flow compatible graph with dual edge keys (`source/target` and `from/to`). |
| `recompute_packet_hash` | `recomputeHash` | `packetJson: string` | `string` (hex) | Calculates deterministic SHA-256 over canonical byte stream. |
| `get_canonical_bytes_hex` | `getCanonicalBytesHex` | `packetJson: string` | `string` (hex) | Encodes canonical bytes into lowercase hex string. |
| `check_scope_permits` | `checkScope` | `scopeJson: string, actionJson: string` | `boolean` | Checks if a CapabilityScope permits a ScopeAction. |
| `meet_capability_scopes` | `meetScopes` | `parentJson: string, childJson: string` | `string` (JSON) | Calculates Capability Lattice meet ($\sqcap$) intersection and `is_bottom` flag. |
| `extract_bundle_files` | `extractBundle` | `zipBytes: Uint8Array` | `Record<string, string>` | Safely unpacks files from ZIP archive into filename-to-content map. Hardened against ZIP bombs. |
| `get_sample_packet` | `getSample` | `sampleType: string` | `string` (JSON) | Returns pre-compiled fixture JSON embedded at compile-time directly from WASM. |
| `generate_keypair` | `generateKeypair` | None | `KeypairResult` | Generates Ed25519 keypair and derives AIP-ID with provenance triple. |

---

## 4. Implementation Blueprint: `src/lib/wasm/types.ts`

```typescript
/**
 * AIP Enterprise Accountability Console - WebAssembly Bridge Types
 * Conforms to PROJECT.md and normative aip-protocol / aip-wasm contracts.
 */

export type TrustFloor =
  | "UNVERIFIED"
  | "AGENT_SIGNED"
  | "AUTHORITY_BOUND"
  | "COUNTERPARTY_SIGNED";

export type RuleName =
  | "STRUCTURE"
  | "AGENT_ID_BINDING"
  | "CANONICAL_HASH"
  | "AGENT_SIGNATURE"
  | "ROOT_TOKEN_SIGNATURE"
  | "DELEGATION_CHAIN"
  | "AUTHORITY_CHAIN"
  | "SCOPE_AUTHORITY"
  | "REVOCATION"
  | "TEMPORAL_VALIDITY"
  | "ACTION_ATTESTATIONS"
  | "TRACE_BINDING"
  | "RECEIPT_BINDING"
  | "TRUST_FLOOR";

export interface RuleResult {
  rule: RuleName | string;
  pass: boolean;
  detail: string;
}

export interface VerificationReport {
  overall_valid: boolean;
  valid?: boolean;
  claimed_trust_floor: TrustFloor;
  derived_trust_floor: TrustFloor;
  trust_floor?: TrustFloor;
  tamper_evidence: boolean;
  tampered?: boolean;
  authority_chain_verified?: boolean;
  delegation_chain_verified?: boolean;
  scope_verified?: boolean;
  receipt_verified?: boolean;
  trace_verified?: boolean;
  revocation_clear?: boolean;
  packet_id: string;
  agent_id: string;
  verified_at: number;
  checks: RuleResult[];
}

export type BundleStatus = "PASS" | "FAIL" | "WARNING" | "Pass" | "Fail" | "Warning";

export interface BundleCheckResult {
  name: string;
  status: BundleStatus;
  pass: boolean;
  detail: string;
}

export interface BundleVerificationResult {
  overall: BundleStatus;
  overall_pass: boolean;
  bundle_id: string;
  packet_id: string;
  signer_fingerprint: string;
  checks: BundleCheckResult[];
}

export type GraphNodeKind =
  | "Principal"
  | "AuthorityGrant"
  | "DelegationHop"
  | "Agent"
  | "Decision"
  | "ActionAttestation"
  | "CountersignedReceipt"
  | string;

export interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  label: string;
  [key: string]: unknown;
}

export interface GraphEdge {
  from: string;
  to: string;
  source: string;
  target: string;
  relation: string;
}

export interface AccountabilityGraph {
  packet_id: string;
  claimed_trust_floor: TrustFloor;
  derived_trust_floor: TrustFloor;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface CapabilityScope {
  allowed: Array<unknown>;
  denied: Array<unknown>;
  is_bottom?: boolean;
}

export interface VerificationContext {
  trusted_issuers?: Record<string, string>;
  issuer_public_keys?: Record<string, string>;
  trusted_counterparties?: Record<string, string>;
  counterparty_public_keys?: Record<string, string>;
  revoked_jtis?: string[];
  trace_data?: string | null;
  receipt_data?: string | null;
}

export interface KeypairResult {
  aip_id: string;
  public_key_hex: string;
  private_key_hex: string;
  public_key_base58: string;
  algorithm: string;
}

export type FixtureCategory =
  | "valid"
  | "unverified_authority"
  | "adversarial"
  | "revocation"
  | "bundle";

export interface FixtureItem {
  id: string;
  title: string;
  category: FixtureCategory;
  description: string;
  filename: string;
  context_filename?: string;
  format?: "json" | "zip";
  claimed_trust_floor?: TrustFloor;
  expected_derived_floor?: TrustFloor;
  expected_valid: boolean;
  expected_tampered?: boolean;
  expected_failed_rules?: RuleName[];
  expected_checks?: string[];
  expected_failed_checks?: string[];
}

export interface LoadedEvidence {
  fileName: string;
  fileType: "json" | "zip";
  packetJson: string;
  contextJson?: string;
  rawBytes?: Uint8Array;
  report?: VerificationReport;
  bundleResult?: BundleVerificationResult;
  graph?: AccountabilityGraph;
  extractedFiles?: Record<string, string>;
}

export interface AipVerifierContextValue {
  isReady: boolean;
  isLoading: boolean;
  error: string | null;
  verifyPacket: (packetJson: string, contextJson?: string) => VerificationReport;
  verifyBundleZip: (zipBytes: Uint8Array, contextJson?: string) => BundleVerificationResult;
  getAccountabilityGraph: (packetJson: string, reportJson?: string) => AccountabilityGraph;
  recomputeHash: (packetJson: string) => string;
  getCanonicalBytesHex: (packetJson: string) => string;
  checkScope: (scopeJson: string, actionJson: string) => boolean;
  meetScopes: (parentJson: string, childJson: string) => string;
  extractBundle: (zipBytes: Uint8Array) => Record<string, string>;
  getSample: (sampleType: string) => string;
  generateKeypair: () => KeypairResult;
  initVerifier: () => Promise<void>;
}
```

---

## 5. Implementation Blueprint: `src/lib/wasm/useAipVerifier.tsx`

```tsx
'use client';

import React, {
  createContext,
  useContext,
  useEffect,
  useState,
  useRef,
  useCallback,
  ReactNode,
} from 'react';
import type {
  AipVerifierContextValue,
  VerificationReport,
  BundleVerificationResult,
  AccountabilityGraph,
  KeypairResult,
} from './types';

// Module-level caches preventing redundant WebAssembly network fetches & compilation
let wasmModulePromise: Promise<any> | null = null;
let wasmModuleInstance: any = null;

async function loadWasm(): Promise<any> {
  if (wasmModuleInstance) return wasmModuleInstance;
  if (wasmModulePromise) return wasmModulePromise;

  wasmModulePromise = (async () => {
    if (typeof window === 'undefined') {
      throw new Error('AIP WebAssembly verifier must run in a client browser environment.');
    }

    try {
      // Dynamic import with webpackIgnore prevents Next.js bundler from attempting SSR bundling
      const wasm = await import(/* webpackIgnore: true */ '/wasm/aip_wasm.js');
      await wasm.default('/wasm/aip_wasm_bg.wasm');

      if (typeof wasm.wasm_init === 'function') {
        try {
          wasm.wasm_init();
        } catch {
          // Hook already registered
        }
      }

      wasmModuleInstance = wasm;
      return wasm;
    } catch (err: any) {
      wasmModulePromise = null;
      throw new Error(`Failed to initialize AIP WebAssembly verifier: ${err?.message || err}`);
    }
  })();

  return wasmModulePromise;
}

const AipVerifierContext = createContext<AipVerifierContextValue | null>(null);

export function AipVerifierProvider({ children }: { children: ReactNode }) {
  const [isReady, setIsReady] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const wasmRef = useRef<any>(null);

  const initVerifier = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const wasm = await loadWasm();
      wasmRef.current = wasm;
      setIsReady(true);
      setIsLoading(false);
    } catch (err: any) {
      setError(err?.message || 'Failed to initialize WebAssembly');
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    initVerifier();
  }, [initVerifier]);

  const verifyPacket = useCallback(
    (packetJson: string, contextJson?: string): VerificationReport => {
      if (!wasmRef.current) {
        throw new Error('AIP WebAssembly verifier is not initialized.');
      }
      const raw = wasmRef.current.verify_evidence_packet(
        packetJson,
        contextJson && contextJson.trim().length > 0 ? contextJson : null
      );
      return JSON.parse(raw) as VerificationReport;
    },
    []
  );

  const verifyBundleZip = useCallback(
    (zipBytes: Uint8Array, contextJson?: string): BundleVerificationResult => {
      if (!wasmRef.current) {
        throw new Error('AIP WebAssembly verifier is not initialized.');
      }
      const raw = wasmRef.current.verify_bundle_zip(
        zipBytes,
        contextJson && contextJson.trim().length > 0 ? contextJson : null
      );
      return JSON.parse(raw) as BundleVerificationResult;
    },
    []
  );

  const getAccountabilityGraph = useCallback(
    (packetJson: string, reportJson?: string): AccountabilityGraph => {
      if (!wasmRef.current) {
        throw new Error('AIP WebAssembly verifier is not initialized.');
      }
      const raw = wasmRef.current.get_accountability_graph(
        packetJson,
        reportJson && reportJson.trim().length > 0 ? reportJson : null
      );
      return JSON.parse(raw) as AccountabilityGraph;
    },
    []
  );

  const recomputeHash = useCallback((packetJson: string): string => {
    if (!wasmRef.current) {
      throw new Error('AIP WebAssembly verifier is not initialized.');
    }
    return wasmRef.current.recompute_packet_hash(packetJson);
  }, []);

  const getCanonicalBytesHex = useCallback((packetJson: string): string => {
    if (!wasmRef.current) {
      throw new Error('AIP WebAssembly verifier is not initialized.');
    }
    return wasmRef.current.get_canonical_bytes_hex(packetJson);
  }, []);

  const checkScope = useCallback((scopeJson: string, actionJson: string): boolean => {
    if (!wasmRef.current) {
      throw new Error('AIP WebAssembly verifier is not initialized.');
    }
    return wasmRef.current.check_scope_permits(scopeJson, actionJson);
  }, []);

  const meetScopes = useCallback((parentJson: string, childJson: string): string => {
    if (!wasmRef.current) {
      throw new Error('AIP WebAssembly verifier is not initialized.');
    }
    return wasmRef.current.meet_capability_scopes(parentJson, childJson);
  }, []);

  const extractBundle = useCallback((zipBytes: Uint8Array): Record<string, string> => {
    if (!wasmRef.current) {
      throw new Error('AIP WebAssembly verifier is not initialized.');
    }
    const raw = wasmRef.current.extract_bundle_files(zipBytes);
    return JSON.parse(raw) as Record<string, string>;
  }, []);

  const getSample = useCallback((sampleType: string): string => {
    if (!wasmRef.current) {
      throw new Error('AIP WebAssembly verifier is not initialized.');
    }
    return wasmRef.current.get_sample_packet(sampleType);
  }, []);

  const generateKeypair = useCallback((): KeypairResult => {
    if (!wasmRef.current) {
      throw new Error('AIP WebAssembly verifier is not initialized.');
    }
    const raw = wasmRef.current.generate_keypair();
    return JSON.parse(raw) as KeypairResult;
  }, []);

  const value: AipVerifierContextValue = {
    isReady,
    isLoading,
    error,
    verifyPacket,
    verifyBundleZip,
    getAccountabilityGraph,
    recomputeHash,
    getCanonicalBytesHex,
    checkScope,
    meetScopes,
    extractBundle,
    getSample,
    generateKeypair,
    initVerifier,
  };

  return <AipVerifierContext.Provider value={value}>{children}</AipVerifierContext.Provider>;
}

export function useAipVerifier(): AipVerifierContextValue {
  const context = useContext(AipVerifierContext);
  if (!context) {
    throw new Error('useAipVerifier must be used within an AipVerifierProvider');
  }
  return context;
}
```

---

## 6. Implementation Blueprint: `src/lib/wasm/fixtures.ts`

```typescript
import type { FixtureItem } from './types';

export const SAMPLE_FIXTURES: FixtureItem[] = [
  {
    id: 'honest_counterparty',
    title: 'Honest Counterparty-Signed Payment',
    category: 'valid',
    format: 'json',
    filename: 'honest_counterparty.json',
    context_filename: 'honest_counterparty.context.json',
    claimed_trust_floor: 'COUNTERPARTY_SIGNED',
    expected_derived_floor: 'COUNTERPARTY_SIGNED',
    expected_valid: true,
    expected_tampered: false,
    expected_failed_rules: [],
    description:
      'Full enterprise payment approval chain with bilateral bank ledger countersignature. Passes all 14 engine verification rules.',
  },
  {
    id: 'authority_bound',
    title: 'Authority-Bound Cloud Scaling',
    category: 'valid',
    format: 'json',
    filename: 'authority_bound.json',
    context_filename: 'authority_bound.context.json',
    claimed_trust_floor: 'AUTHORITY_BOUND',
    expected_derived_floor: 'AUTHORITY_BOUND',
    expected_valid: true,
    expected_tampered: false,
    expected_failed_rules: [],
    description:
      'Autonomous infrastructure scaling action with attenuated delegation. Passes rules 1-12 without external countersignature.',
  },
  {
    id: 'agent_signed',
    title: 'Agent-Signed Autonomous Task',
    category: 'unverified_authority',
    format: 'json',
    filename: 'agent_signed.json',
    context_filename: 'agent_signed.context.json',
    claimed_trust_floor: 'AGENT_SIGNED',
    expected_derived_floor: 'AGENT_SIGNED',
    expected_valid: false,
    expected_tampered: false,
    expected_failed_rules: ['ROOT_TOKEN_SIGNATURE'],
    description:
      'Self-signed web scraping task lacking enterprise principal delegation. Derives AgentSigned trust floor.',
  },
  {
    id: 'tampered_summary',
    title: 'Tampered Decision Summary',
    category: 'adversarial',
    format: 'json',
    filename: 'tampered_summary.json',
    context_filename: 'honest_counterparty.context.json',
    claimed_trust_floor: 'COUNTERPARTY_SIGNED',
    expected_derived_floor: 'UNVERIFIED',
    expected_valid: false,
    expected_tampered: true,
    expected_failed_rules: ['CANONICAL_HASH', 'TRUST_FLOOR'],
    description:
      'Payment amount modified in sealed packet without hash update. Violates CANONICAL_HASH rule.',
  },
  {
    id: 'tampered_hash',
    title: 'Tampered Payload with Recalculated Hash',
    category: 'adversarial',
    format: 'json',
    filename: 'tampered_hash.json',
    context_filename: 'honest_counterparty.context.json',
    claimed_trust_floor: 'COUNTERPARTY_SIGNED',
    expected_derived_floor: 'UNVERIFIED',
    expected_valid: false,
    expected_tampered: true,
    expected_failed_rules: ['AGENT_SIGNATURE', 'TRUST_FLOOR'],
    description:
      'Attacker updated packet_hash after editing payload. Bypasses CANONICAL_HASH but caught by AGENT_SIGNATURE.',
  },
  {
    id: 'tampered_signature',
    title: 'Corrupted Agent Signature',
    category: 'adversarial',
    format: 'json',
    filename: 'tampered_signature.json',
    context_filename: 'honest_counterparty.context.json',
    claimed_trust_floor: 'COUNTERPARTY_SIGNED',
    expected_derived_floor: 'UNVERIFIED',
    expected_valid: false,
    expected_tampered: true,
    expected_failed_rules: ['AGENT_SIGNATURE', 'TRUST_FLOOR'],
    description:
      'Corrupted signature bytes in transit. Violates AGENT_SIGNATURE verification rule.',
  },
  {
    id: 'scope_escalation',
    title: 'Privilege Scope Escalation',
    category: 'adversarial',
    format: 'json',
    filename: 'scope_escalation.json',
    context_filename: 'honest_counterparty.context.json',
    claimed_trust_floor: 'COUNTERPARTY_SIGNED',
    expected_derived_floor: 'UNVERIFIED',
    expected_valid: false,
    expected_tampered: true,
    expected_failed_rules: ['DELEGATION_CHAIN', 'TRUST_FLOOR'],
    description:
      'Delegation hop claims wider scope than granted by root token. Violates DELEGATION_CHAIN rule.',
  },
  {
    id: 'revoked_token',
    title: 'Revoked Delegation Token',
    category: 'revocation',
    format: 'json',
    filename: 'revoked_token.json',
    context_filename: 'revoked_token.context.json',
    claimed_trust_floor: 'COUNTERPARTY_SIGNED',
    expected_derived_floor: 'AGENT_SIGNED',
    expected_valid: false,
    expected_tampered: false,
    expected_failed_rules: ['REVOCATION', 'TRUST_FLOOR'],
    description:
      'Validly sealed packet whose delegation token was revoked after issuance. Violates REVOCATION (not tampered).',
  },
  {
    id: 'audit_bundle_valid',
    title: 'Certified Audit Export Bundle',
    category: 'bundle',
    format: 'zip',
    filename: 'audit_bundle_valid.zip',
    context_filename: 'honest_counterparty.context.json',
    expected_valid: true,
    expected_checks: [
      'BUNDLE_STRUCTURE',
      'MANIFEST_PARSE',
      'FILE_HASHES',
      'BUNDLE_HASH',
      'BUNDLE_SIGNATURE',
      'EVIDENCE_INTEGRITY',
      'PACKET_VERIFICATION',
    ],
    description:
      'Conforming 7-file ZIP archive signed by service key with valid manifest and file checksums.',
  },
  {
    id: 'audit_bundle_tampered',
    title: 'Tampered Audit Export Bundle',
    category: 'bundle',
    format: 'zip',
    filename: 'audit_bundle_tampered.zip',
    expected_valid: false,
    expected_failed_checks: ['FILE_HASHES'],
    description:
      'ZIP bundle with modified evidence.json. FILE_HASHES check detects content tampering.',
  },
];
```

---

## 7. Implementation Blueprint: `src/lib/wasm/EvidenceContext.tsx`

```tsx
'use client';

import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  ReactNode,
} from 'react';
import type {
  VerificationReport,
  BundleVerificationResult,
  AccountabilityGraph,
  LoadedEvidence,
} from './types';
import { useAipVerifier } from './useAipVerifier';
import { SAMPLE_FIXTURES } from './fixtures';

interface EvidenceContextValue {
  evidence: LoadedEvidence | null;
  report: VerificationReport | null;
  graph: AccountabilityGraph | null;
  bundleResult: BundleVerificationResult | null;
  contextJson: string;
  isVerifying: boolean;
  error: string | null;

  loadPacket: (packetJson: string, fileName?: string, contextOverride?: string) => Promise<void>;
  loadBundle: (zipBytes: Uint8Array, fileName?: string, contextOverride?: string) => Promise<void>;
  loadFixture: (fixtureId: string) => Promise<void>;
  updateContext: (newContextJson: string) => void;
  reverify: () => Promise<void>;
  clearEvidence: () => void;
}

const EvidenceContext = createContext<EvidenceContextValue | null>(null);

export function EvidenceProvider({ children }: { children: ReactNode }) {
  const verifier = useAipVerifier();
  const [evidence, setEvidence] = useState<LoadedEvidence | null>(null);
  const [report, setReport] = useState<VerificationReport | null>(null);
  const [graph, setGraph] = useState<AccountabilityGraph | null>(null);
  const [bundleResult, setBundleResult] = useState<BundleVerificationResult | null>(null);
  const [contextJson, setContextJson] = useState<string>('{}');
  const [isVerifying, setIsVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadPacket = useCallback(
    async (packetJson: string, fileName = 'evidence.json', contextOverride?: string) => {
      setIsVerifying(true);
      setError(null);
      try {
        const activeContext = contextOverride ?? contextJson;
        const rep = verifier.verifyPacket(packetJson, activeContext);
        const gr = verifier.getAccountabilityGraph(packetJson, JSON.stringify(rep));

        setReport(rep);
        setGraph(gr);
        setBundleResult(null);
        if (contextOverride !== undefined) {
          setContextJson(contextOverride);
        }
        setEvidence({
          fileName,
          fileType: 'json',
          packetJson,
          contextJson: activeContext,
          report: rep,
          graph: gr,
        });
      } catch (err: any) {
        setError(err?.message || 'Verification failed');
      } finally {
        setIsVerifying(false);
      }
    },
    [verifier, contextJson]
  );

  const loadBundle = useCallback(
    async (zipBytes: Uint8Array, fileName = 'audit_bundle.zip', contextOverride?: string) => {
      setIsVerifying(true);
      setError(null);
      try {
        const activeContext = contextOverride ?? contextJson;
        const bResult = verifier.verifyBundleZip(zipBytes, activeContext);
        const extracted = verifier.extractBundle(zipBytes);

        let rep: VerificationReport | null = null;
        let gr: AccountabilityGraph | null = null;
        let packetJson = '';

        if (extracted['evidence.json']) {
          packetJson = extracted['evidence.json'];
          rep = verifier.verifyPacket(packetJson, activeContext);
          gr = verifier.getAccountabilityGraph(packetJson, JSON.stringify(rep));
        }

        setBundleResult(bResult);
        setReport(rep);
        setGraph(gr);
        if (contextOverride !== undefined) {
          setContextJson(contextOverride);
        }
        setEvidence({
          fileName,
          fileType: 'zip',
          packetJson,
          contextJson: activeContext,
          rawBytes: zipBytes,
          report: rep || undefined,
          bundleResult: bResult,
          graph: gr || undefined,
          extractedFiles: extracted,
        });
      } catch (err: any) {
        setError(err?.message || 'Bundle verification failed');
      } finally {
        setIsVerifying(false);
      }
    },
    [verifier, contextJson]
  );

  const loadFixture = useCallback(
    async (fixtureId: string) => {
      const fixture = SAMPLE_FIXTURES.find((f) => f.id === fixtureId);
      if (!fixture) throw new Error(`Unknown fixture: ${fixtureId}`);

      let ctx = '{}';
      if (fixture.context_filename) {
        try {
          ctx = verifier.getSample(fixture.context_filename);
        } catch {
          const res = await fetch(`/fixtures/${fixture.context_filename}`);
          if (res.ok) ctx = await res.text();
        }
      }

      if (fixture.format === 'zip') {
        const res = await fetch(`/fixtures/${fixture.filename}`);
        if (!res.ok) throw new Error(`Failed to fetch ${fixture.filename}`);
        const buf = await res.arrayBuffer();
        await loadBundle(new Uint8Array(buf), fixture.filename, ctx);
      } else {
        let packet = '';
        try {
          packet = verifier.getSample(fixture.id);
        } catch {
          const res = await fetch(`/fixtures/${fixture.filename}`);
          if (!res.ok) throw new Error(`Failed to fetch ${fixture.filename}`);
          packet = await res.text();
        }
        await loadPacket(packet, fixture.filename, ctx);
      }
    },
    [verifier, loadBundle, loadPacket]
  );

  const reverify = useCallback(async () => {
    if (!evidence) return;
    if (evidence.fileType === 'zip' && evidence.rawBytes) {
      await loadBundle(evidence.rawBytes, evidence.fileName, contextJson);
    } else if (evidence.packetJson) {
      await loadPacket(evidence.packetJson, evidence.fileName, contextJson);
    }
  }, [evidence, contextJson, loadBundle, loadPacket]);

  const updateContext = useCallback((newContextJson: string) => {
    setContextJson(newContextJson);
  }, []);

  const clearEvidence = useCallback(() => {
    setEvidence(null);
    setReport(null);
    setGraph(null);
    setBundleResult(null);
    setError(null);
  }, []);

  return (
    <EvidenceContext.Provider
      value={{
        evidence,
        report,
        graph,
        bundleResult,
        contextJson,
        isVerifying,
        error,
        loadPacket,
        loadBundle,
        loadFixture,
        updateContext,
        reverify,
        clearEvidence,
      }}
    >
      {children}
    </EvidenceContext.Provider>
  );
}

export function useEvidence() {
  const context = useContext(EvidenceContext);
  if (!context) {
    throw new Error('useEvidence must be used within an EvidenceProvider');
  }
  return context;
}
```

---

## 8. Implementation Blueprint: `src/components/ingestion/Dropzone.tsx`

```tsx
'use client';

import React, { useState, useRef, useCallback, DragEvent, ChangeEvent } from 'react';
import {
  Upload,
  FileJson,
  Archive,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  Sparkles,
  X,
  FileCode,
  ShieldCheck,
  ChevronRight,
} from 'lucide-react';
import { useEvidence } from '@/lib/wasm/EvidenceContext';
import { useAipVerifier } from '@/lib/wasm/useAipVerifier';
import { SAMPLE_FIXTURES } from '@/lib/wasm/fixtures';

export function Dropzone() {
  const { isReady, isLoading: isWasmLoading } = useAipVerifier();
  const {
    evidence,
    report,
    bundleResult,
    isVerifying,
    error,
    loadPacket,
    loadBundle,
    loadFixture,
    clearEvidence,
  } = useEvidence();

  const [isDragActive, setIsDragActive] = useState(false);
  const [activeTab, setActiveTab] = useState<'all' | 'valid' | 'adversarial' | 'bundle'>('all');
  const [showAllFixtures, setShowAllFixtures] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFiles = useCallback(
    async (files: FileList | null) => {
      if (!files || files.length === 0) return;
      const file = files[0];
      const isZip = file.name.endsWith('.zip');
      const isJson = file.name.endsWith('.json');

      if (!isZip && !isJson) {
        alert('Unsupported file type. Please upload a .json EvidencePacket or .zip Audit Bundle.');
        return;
      }

      const reader = new FileReader();
      if (isZip) {
        reader.onload = async (e) => {
          const buffer = e.target?.result as ArrayBuffer;
          await loadBundle(new Uint8Array(buffer), file.name);
        };
        reader.readAsArrayBuffer(file);
      } else {
        reader.onload = async (e) => {
          const text = e.target?.result as string;
          await loadPacket(text, file.name);
        };
        reader.readAsText(file);
      }
    },
    [loadBundle, loadPacket]
  );

  const onDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(true);
  };

  const onDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
  };

  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
    handleFiles(e.dataTransfer.files);
  };

  const onFileInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    handleFiles(e.target.files);
  };

  const quickFixtures = [
    { id: 'honest_counterparty', label: '⚡ Honest Payment', desc: 'Valid Level 3' },
    { id: 'authority_bound', label: '🛡️ Cloud Scaling', desc: 'Valid Level 2' },
    { id: 'tampered_summary', label: '⚠️ Tampered Summary', desc: 'Adversarial' },
    { id: 'revoked_token', label: '🚫 Revoked Token', desc: 'Revocation' },
    { id: 'audit_bundle_valid', label: '📦 Audit ZIP', desc: 'Conforming Bundle' },
  ];

  const filteredFixtures = SAMPLE_FIXTURES.filter((f) => {
    if (activeTab === 'all') return true;
    if (activeTab === 'valid') return f.category === 'valid';
    if (activeTab === 'adversarial') return f.category === 'adversarial';
    if (activeTab === 'bundle') return f.category === 'bundle';
    return true;
  });

  return (
    <div className="w-full space-y-4">
      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".json,.zip,application/json,application/zip"
        className="hidden"
        onChange={onFileInputChange}
      />

      {/* Main Drag-and-Drop Area */}
      <div
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        onClick={() => !isVerifying && fileInputRef.current?.click()}
        className={`relative group cursor-pointer overflow-hidden rounded-xl border-2 border-dashed p-8 text-center transition-all duration-300 ${
          isDragActive
            ? 'border-[#00E5FF] bg-[#00E5FF]/10 shadow-[0_0_35px_rgba(0,229,255,0.25)] ring-2 ring-[#00E5FF]/40'
            : 'border-[#222F46] bg-[#0E131F]/90 hover:border-[#00E5FF]/60 hover:bg-[#0E131F]'
        }`}
      >
        {/* Subtle Ambient Radial Highlight */}
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-[#00E5FF]/10 via-transparent to-transparent opacity-60" />

        <div className="relative z-10 flex flex-col items-center justify-center space-y-3">
          {/* Status Indicator Icon */}
          {isVerifying || isWasmLoading ? (
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-[#00E5FF]/10 text-[#00E5FF] ring-1 ring-[#00E5FF]/30">
              <Loader2 className="h-8 w-8 animate-spin" />
            </div>
          ) : evidence ? (
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-[#00E676]/10 text-[#00E676] ring-1 ring-[#00E676]/30">
              <CheckCircle2 className="h-8 w-8" />
            </div>
          ) : (
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-[#161F33] text-[#00E5FF] ring-1 ring-[#222F46] group-hover:scale-105 group-hover:border-[#00E5FF]/50 transition-all duration-200">
              <Upload className="h-8 w-8" />
            </div>
          )}

          {/* Heading and Guidance */}
          {isWasmLoading ? (
            <div>
              <p className="text-base font-semibold text-slate-200">
                Initializing WebAssembly Verification Engine...
              </p>
              <p className="text-xs text-slate-400">Loading compiled Rust aip-protocol binary</p>
            </div>
          ) : isVerifying ? (
            <div>
              <p className="text-base font-semibold text-[#00E5FF]">
                Cryptographically Verifying Evidence...
              </p>
              <p className="text-xs text-slate-400">Evaluating 14 non-short-circuiting rules in WebAssembly</p>
            </div>
          ) : evidence ? (
            <div className="space-y-1">
              <div className="flex items-center justify-center gap-2">
                <span className="font-mono text-sm font-semibold text-slate-200">
                  {evidence.fileName}
                </span>
                <span className="rounded bg-[#161F33] px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-[#00E5FF] border border-[#222F46]">
                  {evidence.fileType}
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Click or drop a new file to replace current evidence
              </p>
            </div>
          ) : (
            <div>
              <p className="text-base font-semibold text-slate-200 group-hover:text-white transition-colors">
                Drop EvidencePacket <span className="text-[#00E5FF]">(.json)</span> or Audit Bundle <span className="text-[#00E5FF]">(.zip)</span>
              </p>
              <p className="text-xs text-slate-400 mt-1">
                or click to browse local filesystem • Instant zero-JS offline verification
              </p>
            </div>
          )}

          {/* Format Badges */}
          <div className="flex items-center gap-2 pt-1 text-[11px] text-slate-400 font-mono">
            <span className="inline-flex items-center gap-1 rounded bg-[#161F33]/80 px-2.5 py-1 border border-[#222F46]">
              <FileJson className="h-3 w-3 text-[#00E5FF]" /> JSON Packet v1
            </span>
            <span className="inline-flex items-center gap-1 rounded bg-[#161F33]/80 px-2.5 py-1 border border-[#222F46]">
              <Archive className="h-3 w-3 text-[#6366F1]" /> Certified ZIP Bundle
            </span>
          </div>
        </div>
      </div>

      {/* Error Alert Box */}
      {error && (
        <div className="flex items-start justify-between rounded-lg border border-[#FF1744]/40 bg-[#FF1744]/10 p-4 text-[#FF1744]">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-bold uppercase tracking-wider">Verification Error</p>
              <p className="text-xs text-slate-300 mt-0.5 font-mono">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Quick Load Sample Strip */}
      <div className="rounded-xl border border-[#222F46] bg-[#0E131F] p-4">
        <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-[#222F46]/60">
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-[#00E5FF]" />
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-200">
              Quick Load Test Fixtures
            </span>
          </div>
          <button
            type="button"
            onClick={() => setShowAllFixtures(!showAllFixtures)}
            className="flex items-center gap-1 text-xs font-medium text-[#00E5FF] hover:underline"
          >
            {showAllFixtures ? 'Hide Fixture Catalog' : 'Browse All 10 Fixtures'}
            <ChevronRight className={`h-3 w-3 transition-transform ${showAllFixtures ? 'rotate-90' : ''}`} />
          </button>
        </div>

        {/* 5 Quick-Click Scenario Buttons */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2 pt-3">
          {quickFixtures.map((qf) => (
            <button
              key={qf.id}
              type="button"
              disabled={isVerifying || !isReady}
              onClick={(e) => {
                e.stopPropagation();
                loadFixture(qf.id);
              }}
              className="flex flex-col items-start rounded-lg border border-[#222F46] bg-[#161F33]/60 p-2.5 text-left transition-all hover:border-[#00E5FF]/60 hover:bg-[#161F33] hover:shadow-[0_0_15px_rgba(0,229,255,0.15)] disabled:opacity-50"
            >
              <span className="text-xs font-semibold text-slate-200">{qf.label}</span>
              <span className="text-[10px] text-slate-400 mt-0.5 font-mono">{qf.desc}</span>
            </button>
          ))}
        </div>

        {/* Expanded 10-Fixture Catalog Drawer */}
        {showAllFixtures && (
          <div className="mt-4 pt-4 border-t border-[#222F46] space-y-3">
            {/* Category Filter Pills */}
            <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
              {(['all', 'valid', 'adversarial', 'bundle'] as const).map((tab) => (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setActiveTab(tab)}
                  className={`rounded-full px-3 py-1 font-medium capitalize transition-all ${
                    activeTab === tab
                      ? 'bg-[#00E5FF] text-[#080B11] font-bold shadow-[0_0_10px_rgba(0,229,255,0.3)]'
                      : 'bg-[#161F33] text-slate-400 hover:text-slate-200 border border-[#222F46]'
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>

            {/* Fixtures List Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 max-h-72 overflow-y-auto pr-1">
              {filteredFixtures.map((fx) => (
                <div
                  key={fx.id}
                  onClick={() => loadFixture(fx.id)}
                  className="flex items-start justify-between rounded-lg border border-[#222F46] bg-[#161F33]/40 p-3 hover:border-[#00E5FF]/50 hover:bg-[#161F33] cursor-pointer transition-all group"
                >
                  <div className="space-y-1 pr-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-slate-200 group-hover:text-[#00E5FF] transition-colors">
                        {fx.title}
                      </span>
                      <span
                        className={`rounded px-1.5 py-0.2 text-[9px] font-bold uppercase tracking-wider ${
                          fx.category === 'valid'
                            ? 'bg-[#00E676]/10 text-[#00E676] border border-[#00E676]/30'
                            : fx.category === 'adversarial'
                            ? 'bg-[#FF1744]/10 text-[#FF1744] border border-[#FF1744]/30'
                            : fx.category === 'bundle'
                            ? 'bg-[#6366F1]/10 text-[#6366F1] border border-[#6366F1]/30'
                            : 'bg-[#FFB300]/10 text-[#FFB300] border border-[#FFB300]/30'
                        }`}
                      >
                        {fx.category}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-snug line-clamp-2">
                      {fx.description}
                    </p>
                  </div>
                  <span className="font-mono text-[10px] text-slate-500 whitespace-nowrap mt-0.5">
                    .{fx.format || 'json'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Active Evidence Summary Bar (If Evidence Loaded) */}
      {evidence && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-[#222F46] bg-[#0E131F] p-4 text-xs">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-[#161F33] text-[#00E5FF] border border-[#222F46]">
              {evidence.fileType === 'zip' ? (
                <Archive className="h-5 w-5" />
              ) : (
                <FileCode className="h-5 w-5" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-slate-200">{evidence.fileName}</span>
                {report && (
                  <span
                    className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                      report.overall_valid
                        ? 'bg-[#00E676]/10 text-[#00E676] border border-[#00E676]/30'
                        : 'bg-[#FF1744]/10 text-[#FF1744] border border-[#FF1744]/30'
                    }`}
                  >
                    {report.overall_valid ? '14/14 Rules Passed' : 'Verification Failed'}
                  </span>
                )}
                {bundleResult && (
                  <span
                    className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                      bundleResult.overall_pass
                        ? 'bg-[#00E676]/10 text-[#00E676] border border-[#00E676]/30'
                        : 'bg-[#FF1744]/10 text-[#FF1744] border border-[#FF1744]/30'
                    }`}
                  >
                    Bundle {bundleResult.overall}
                  </span>
                )}
              </div>
              <p className="font-mono text-[11px] text-slate-400 mt-0.5">
                {report?.packet_id ? `ID: ${report.packet_id}` : bundleResult ? `Bundle: ${bundleResult.bundle_id}` : ''}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={clearEvidence}
              className="flex items-center gap-1 rounded-lg border border-[#222F46] bg-[#161F33] px-3 py-1.5 font-medium text-slate-300 hover:border-[#FF1744]/60 hover:text-[#FF1744] transition-all"
            >
              <X className="h-3.5 w-3.5" /> Clear
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
```

---

## 9. Verification & Safety Analysis

1. **Hydration Verification**:
   - `useAipVerifier` only initiates the `loadWasm()` promise in a client-side `useEffect()`. During server prerender, `isReady` is `false`, `isLoading` is `true`, and initial HTML is identical on server and client.
2. **ZIP Security Verification**:
   - The Rust engine enforces `MAX_BUNDLE_ENTRIES = 128`, `MAX_ENTRY_SIZE = 10 MiB`, and `MAX_TOTAL_BUNDLE_SIZE = 50 MiB`.
   - File extraction in `extract_bundle_files` guards against ZIP bombs and memory exhaustion at the WASM boundary.
3. **1:1 Rule Verification**:
   - Ingestion dropzone passes raw payloads directly to `wasm.verify_evidence_packet` and `wasm.verify_bundle_zip`. No validation or heuristic scoring occurs in JavaScript.
