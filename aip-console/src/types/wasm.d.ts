declare module "/wasm/aip_wasm.js" {
  export default function init(module_or_path?: string | URL | Request | WebAssembly.Module): Promise<any>;
  export function wasm_init(): void;
  export function verify_evidence_packet(packet_json: string, context_json?: string | null): string;
  export function verify_bundle_zip(zip_bytes: Uint8Array | number[], context_json?: string | null): string;
  export function get_accountability_graph(packet_json: string, report_json?: string | null): string;
  export function recompute_packet_hash(packet_json: string): string;
  export function get_canonical_bytes_hex(packet_json: string): string;
  export function check_scope_permits(scope_json: string, action_json: string): boolean;
  export function meet_capability_scopes(parent_json: string, child_json: string): string;
  export function extract_bundle_files(zip_bytes: Uint8Array | number[]): string;
  export function get_sample_packet(sample_type: string): string;
  export function generate_keypair(): string;
}
