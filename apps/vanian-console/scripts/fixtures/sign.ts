import { generateKeyPairSync, sign } from "node:crypto";
import { writeFileSync } from "node:fs";
import { demoEvents } from "../../src/server/fixtures";
import { digest, signedMessage, groupBatches } from "../../src/server/proof";
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const batches: Record<
  string,
  { hash: string; count: number; signature: string }
> = {};
for (const [id, rows] of groupBatches(demoEvents())) {
  const hash = await digest(rows);
  batches[id] = {
    hash,
    count: rows.length,
    signature: sign(
      null,
      signedMessage(id, rows.length, hash),
      privateKey,
    ).toString("base64"),
  };
}
writeFileSync(
  "src/server/demo-proof.json",
  JSON.stringify(
    { publicKey: publicKey.export({ format: "jwk" }), batches },
    null,
    2,
  ) + "\n",
);
