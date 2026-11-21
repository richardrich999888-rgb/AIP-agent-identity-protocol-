import { readFile } from "node:fs/promises";
import { createHash, createPublicKey, verify } from "node:crypto";
const file = process.argv[2];
if (!file) throw Error("Supply the downloaded batch JSON file.");
const data = JSON.parse(await readFile(file, "utf8"));
const key = process.argv[3]
  ? JSON.parse(await readFile(process.argv[3], "utf8"))
  : JSON.parse(
      await readFile(new URL("../src/server/demo-proof.json", import.meta.url)),
    ).publicKey;
if (
  data.mode !== "demo" ||
  data.schema !== "VANIAN-DEMO-v1" ||
  !Array.isArray(data.events)
)
  throw Error("Unsupported batch format.");
const payload = data.events
  .map((e) =>
    JSON.stringify(
      Object.fromEntries(
        Object.keys(e)
          .sort()
          .map((k) => [k, e[k]]),
      ),
    ),
  )
  .sort()
  .join("\n");
const digest = createHash("sha256").update(payload).digest("hex");
const message = Buffer.from(
  JSON.stringify([data.schema, data.id, data.events.length, digest]),
);
const accepted =
  digest === data.hash &&
  data.count === data.events.length &&
  data.events.every((e) => e.batch === data.id) &&
  verify(
    null,
    message,
    createPublicKey({ key, format: "jwk" }),
    Buffer.from(data.signature, "base64"),
  );
console.log(
  JSON.stringify({
    mode: "demo",
    id: data.id,
    accepted,
    digest,
    events: data.events.length,
  }),
);
process.exitCode = accepted ? 0 : 1;
