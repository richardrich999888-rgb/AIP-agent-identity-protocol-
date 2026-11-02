/* tslint:disable */
/* eslint-disable */

/**
 * 6. Check if CapabilityScope permits a ScopeAction.
 */
export function check_scope_permits(scope_json: string, action_json: string): boolean;

/**
 * 8. Extract all content files from ZIP bundle bytes.
 * Returns JSON map of filename -> content text.
 * Hardened with in-memory size limits to guard against ZIP bombs and memory exhaustion.
 */
export function extract_bundle_files(zip_bytes: Uint8Array | number[]): string;

/**
 * 9. Generate Ed25519 keypair and derive AIP-ID with provenance.
 */
export function generate_keypair(): string;

/**
 * 3. Reconstruct AccountabilityGraph from EvidencePacket JSON & optional VerificationReport JSON.
 * Returns JSON graph with React Flow dual edge support (from/to and source/target).
 */
export function get_accountability_graph(packet_json: string, report_json?: string | null): string;

/**
 * 5. Get canonical encoding bytes as lowercase hex string.
 */
export function get_canonical_bytes_hex(packet_json: string): string;

/**
 * 10. Sample packet fixture provider.
 * Serves static pre-compiled JSON fixture strings directly from compile-time embedded strings.
 */
export function get_sample_packet(sample_type: string): string;

/**
 * 7. Compute Capability Lattice intersection (MEET operator ⊓).
 */
export function meet_capability_scopes(parent_json: string, child_json: string): string;

/**
 * 4. Recompute SHA-256 packet hash over canonical bytes.
 */
export function recompute_packet_hash(packet_json: string): string;

/**
 * 2. Verify audit export ZIP bundle bytes against optional context.
 * Returns JSON BundleVerificationResult.
 */
export function verify_bundle_zip(zip_bytes: Uint8Array | number[], context_json?: string | null): string;

/**
 * 1. Verify EvidencePacket JSON against optional VerificationContext JSON.
 * Returns JSON VerificationReport with dual-compatibility keys.
 */
export function verify_evidence_packet(packet_json: string, context_json?: string | null): string;

export function wasm_init(): void;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly check_scope_permits: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly extract_bundle_files: (a: number, b: number) => [number, number, number, number];
    readonly generate_keypair: () => [number, number, number, number];
    readonly get_accountability_graph: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly get_canonical_bytes_hex: (a: number, b: number) => [number, number, number, number];
    readonly get_sample_packet: (a: number, b: number) => [number, number, number, number];
    readonly meet_capability_scopes: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly recompute_packet_hash: (a: number, b: number) => [number, number, number, number];
    readonly verify_bundle_zip: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly verify_evidence_packet: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly wasm_init: () => void;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
