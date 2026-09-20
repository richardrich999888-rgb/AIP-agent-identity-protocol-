/**
 * Crypto primitives shared by the agent-identity and agent-accountability
 * layers: canonical JSON, SHA-256 digests, and HMAC-SHA-256 signatures.
 *
 * # Why canonical JSON exists here
 *
 * Both the credential signature and the ledger hash chain sign *serialized*
 * objects, and `JSON.stringify` key order follows insertion order — two
 * structurally identical objects can serialize differently and a verifier
 * would call an untampered record forged. Every signed or hashed payload in
 * this subsystem therefore goes through `canonicalJson`, which sorts object
 * keys recursively so the bytes are a function of the value alone.
 *
 * # Why HMAC rather than Ed25519
 *
 * WebCrypto's Ed25519 support is still uneven across the browsers this
 * console targets, and the registry that issues credentials is the same
 * runtime that verifies them — there is no third-party verifier that would
 * need a public key. HMAC-SHA-256 gives the same tamper-evidence for this
 * trust model with universally available primitives. If credentials ever
 * need to be verified outside the issuing console, this is the seam where
 * Ed25519 slots in.
 */

/** Resolves the WebCrypto implementation, failing loudly rather than letting
 * a missing API turn every signature into an unhandled rejection later. */
function subtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new Error(
      "WebCrypto (crypto.subtle) is unavailable in this runtime; " +
        "agent credentials and the audit ledger cannot operate without it.",
    );
  }
  return c.subtle;
}

/** JSON value type accepted by the canonical serializer. */
export type Jsonish =
  | string
  | number
  | boolean
  | null
  | undefined
  | Jsonish[]
  | { [key: string]: Jsonish };

/**
 * Deterministic JSON: object keys sorted recursively, `undefined` properties
 * dropped (matching `JSON.stringify`), arrays kept in order — order inside an
 * array is data, order inside an object is not.
 */
export function canonicalJson(value: Jsonish): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalJson(v ?? null)).join(",")}]`;
  }
  const keys = Object.keys(value)
    .filter((k) => value[k] !== undefined)
    .sort();
  const body = keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`);
  return `{${body.join(",")}}`;
}

function toHex(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

const encoder = new TextEncoder();

/** Optional synchronous SHA-256 override. The WASM bridge installs the
 * Rust core's digest here once it initializes, so every seal, chain link,
 * and proof in the telemetry stack routes through the same deterministic
 * core the offline verifier runs — Web Crypto stays the fallback. This
 * module deliberately imports nothing from the bridge (the bridge's own
 * fallback imports this module), so the seam is a setter, not an import. */
let sha256Provider: ((text: string) => string) | null = null;

/** Installs (or, with null, removes) the synchronous SHA-256 provider. */
export function installSha256Provider(provider: ((text: string) => string) | null): void {
  sha256Provider = provider;
}

/** SHA-256 of a UTF-8 string, as lowercase hex. */
export async function sha256Hex(text: string): Promise<string> {
  if (sha256Provider) return sha256Provider(text);
  return toHex(await subtle().digest("SHA-256", encoder.encode(text)));
}

/** Imports a secret string as an HMAC-SHA-256 signing key. */
export async function importHmacKey(secret: string): Promise<CryptoKey> {
  return subtle().importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/** HMAC-SHA-256 signature of a UTF-8 string, as lowercase hex. */
export async function hmacSignHex(key: CryptoKey, text: string): Promise<string> {
  return toHex(await subtle().sign("HMAC", key, encoder.encode(text)));
}

/** Verifies an HMAC produced by {@link hmacSignHex}. Constant-time via
 * WebCrypto's own verify rather than a string compare. */
export async function hmacVerifyHex(
  key: CryptoKey,
  text: string,
  signatureHex: string,
): Promise<boolean> {
  if (!/^[0-9a-f]+$/.test(signatureHex) || signatureHex.length % 2 !== 0) {
    return false;
  }
  const sig = new Uint8Array(signatureHex.length / 2);
  for (let i = 0; i < sig.length; i++) {
    sig[i] = parseInt(signatureHex.slice(i * 2, i * 2 + 2), 16);
  }
  return subtle().verify("HMAC", key, sig, encoder.encode(text));
}
