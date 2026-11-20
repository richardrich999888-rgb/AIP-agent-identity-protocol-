import fixture from "./demo-proof.json";
import { allEvents } from "./fixtures";
import { checkBatch, groupBatches } from "./proof";
const proofs: Record<
  string,
  { hash: string; count: number; signature: string }
> = fixture.batches;
let collection: ReturnType<typeof groupBatches> | undefined;
export function batches() {
  return (collection ??= groupBatches(allEvents()));
}
let publicKey: Promise<CryptoKey> | undefined;
const results = new Map<string, Promise<boolean>>();
export function verify(id: string) {
  if (!proofs[id] || !batches().has(id)) return Promise.resolve(false);
  if (!results.has(id)) {
    publicKey ??= crypto.subtle.importKey(
      "jwk",
      fixture.publicKey,
      "Ed25519",
      false,
      ["verify"],
    );
    results.set(
      id,
      publicKey
        .then((k) => checkBatch(k, id, batches().get(id)!, proofs[id]))
        .catch(() => false),
    );
  }
  return results.get(id)!;
}
export async function exportBatch(id: string) {
  const proof = proofs[id];
  if (!proof) return null;
  return {
    schema: "VANIAN-DEMO-v1",
    mode: "demo",
    source: "Signed synthetic telemetry",
    id,
    algorithm: "Ed25519",
    digestAlgorithm: "SHA-256",
    verified: await verify(id),
    publicKey: fixture.publicKey,
    ...proof,
    events: batches().get(id),
  };
}
