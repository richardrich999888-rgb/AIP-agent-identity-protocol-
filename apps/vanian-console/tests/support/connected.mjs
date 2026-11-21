import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createReader } from "../../bridge/service.mjs";
import { testSite } from "./site.mjs";

export async function connectedSite() {
  const folder = await mkdtemp(join(tmpdir(), "vanian-evaluation-ui-"));
  const subject = "evaluation-subject",
    tenant = "ephemeral-test-tenant",
    token = randomBytes(32).toString("hex");
  try {
    await promisify(execFile)(process.env.SELF_SAMPLE_GENERATOR, [folder]);
    const trust = JSON.parse(
      await readFile(join(folder, "anchor.json"), "utf8"),
    );
    const read = createReader(
      {
        tenant,
        group: "Engineering",
        members: { [subject]: "Analyst" },
        sourceClassification: "customer-runtime",
        observer: {
          ...trust,
          binary: process.env.OBSERVER_VERIFIER,
          batches: join(folder, "batches.jsonl"),
          health: join(folder, "health.jsonl"),
        },
      },
      token,
    );
    const site = await testSite({
      bindings: {
        VANIAN_API_ORIGIN: "https://reader.invalid",
        VANIAN_API_TOKEN: token,
        VANIAN_LIVE_MEMBERS: JSON.stringify({
          [subject]: { tenant, role: "Analyst" },
        }),
      },
      outboundService: async (request) => {
        if (new URL(request.url).origin !== "https://reader.invalid")
          return new Response("Unexpected source", { status: 503 });
        const response = await read(request);
        return new Response(await response.text(), {
          status: response.status,
          headers: Object.fromEntries(response.headers),
        });
      },
    });
    return {
      url: site.url,
      subject,
      async close() {
        try {
          await site.mf.dispose();
        } finally {
          await rm(folder, { recursive: true, force: true });
        }
      },
    };
  } catch (error) {
    await rm(folder, { recursive: true, force: true });
    throw error;
  }
}
