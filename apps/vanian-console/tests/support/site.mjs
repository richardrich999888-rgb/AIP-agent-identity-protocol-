import { Miniflare } from "miniflare";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
export async function testSite(options = {}) {
  const root = path.resolve("dist/server");
  const files = (await readdir(root, { recursive: true }))
    .filter((f) => f.endsWith(".js") || f.endsWith(".mjs"))
    .sort((a, b) => Number(b === "index.js") - Number(a === "index.js"));
  const modules = await Promise.all(
    files.map(async (name) => ({
      type: "ESModule",
      path: path.join(root, name),
      contents: await readFile(path.join(root, name)),
    })),
  );
  const mf = new Miniflare({
    modulesRoot: root,
    modules,
    compatibilityDate: "2026-05-15",
    compatibilityFlags: ["nodejs_compat"],
    d1Databases: ["DB"],
    assets: {
      directory: path.resolve("dist/client"),
      routerConfig: { has_user_worker: true },
    },
    ...options,
    inspectorPort: 0,
    host: "127.0.0.1",
    port: 0,
  });
  const db = await mf.getD1Database("DB");
  for (const f of (await readdir("drizzle"))
    .filter((n) => n.endsWith(".sql"))
    .sort()) {
    for (const stmt of (await readFile("drizzle/" + f, "utf8")).split(
      "--> statement-breakpoint",
    ))
      if (stmt.trim()) await db.prepare(stmt.trim()).run();
  }
  return { mf, url: (await mf.ready).origin };
}
