import type { Exec } from "../types";
export const canonical = (e: Exec) =>
  JSON.stringify(
    Object.fromEntries(
      Object.keys(e)
        .sort()
        .map((k) => [k, e[k as keyof Exec]]),
    ),
  );
export const hex = (data: ArrayBuffer) =>
  Array.from(new Uint8Array(data), (x) => x.toString(16).padStart(2, "0")).join(
    "",
  );
export async function digest(items: Exec[]) {
  const text = items.map(canonical).sort().join("\n");
  return hex(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)),
  );
}
export const signedMessage = (id: string, count: number, hash: string) =>
  new TextEncoder().encode(JSON.stringify(["VANIAN-DEMO-v1", id, count, hash]));
export const bytes = (s: string) =>
  Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
export function groupBatches(events: Exec[]) {
  const m = new Map<string, Exec[]>();
  for (const e of events) {
    const a = m.get(e.batch) ?? [];
    a.push(e);
    m.set(e.batch, a);
  }
  return m;
}
export async function checkBatch(
  key: CryptoKey,
  id: string,
  items: Exec[],
  proof: { count: number; hash: string; signature: string },
) {
  const h = await digest(items);
  return (
    h === proof.hash &&
    proof.count === items.length &&
    (await crypto.subtle.verify(
      "Ed25519",
      key,
      bytes(proof.signature),
      signedMessage(id, items.length, h),
    ))
  );
}
