import { readdir, readFile } from "node:fs/promises";
import { Miniflare } from "miniflare";
import path from "node:path";
const config = JSON.parse(await readFile("dist/server/wrangler.json", "utf8"));
const id = config.d1_databases?.find((b) => b.binding === "DB")?.database_id;
if (!id)
  throw Error(
    "Build the DB-enabled Worker before initializing the local environment.",
  );
const mf = new Miniflare({
  modules: true,
  script: "export default {fetch(){return new Response('local migration')}}",
  d1Databases: { DB: id },
  d1Persist: path.resolve(".wrangler/state/v3/d1"),
  compatibilityDate: config.compatibility_date,
});
try {
  const db = await mf.getD1Database("DB");
  await db
    .prepare(
      "CREATE TABLE IF NOT EXISTS d1_migrations(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL)",
    )
    .run();
  for (const name of (await readdir("drizzle"))
    .filter((f) => f.endsWith(".sql"))
    .sort()) {
    if (
      await db
        .prepare("SELECT name FROM d1_migrations WHERE name=?")
        .bind(name)
        .first()
    )
      continue;
    const sql = (await readFile("drizzle/" + name, "utf8"))
      .split("--> statement-breakpoint")
      .map((s) => s.trim())
      .filter(Boolean);
    // The local preview may have executed the initial DDL before a migration ledger existed.
    // Adopt it only when the complete schema matches the tracked baseline.
    let statements = sql;
    if (name.startsWith("0000_")) {
      const schemas = await Promise.all(
        sql.map(async (statement) => {
          const item = statement.match(/^CREATE TABLE `(\w+)`/i);
          if (!item) return { expected: statement, existing: null };
          const result = await db
            .prepare(
              "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            )
            .bind(item[1])
            .first();
          return { expected: statement, existing: result?.sql };
        }),
      );
      if (schemas.some((item) => item.existing)) {
        const normalized = (s) =>
          s.trim().replace(/;$/, "").replace(/\s+/g, " ");
        if (
          !schemas.every(
            (item) =>
              item.existing &&
              normalized(item.existing) === normalized(item.expected),
          )
        )
          throw new Error(
            "The existing local schema differs from the tracked baseline. Export the database and reconcile the schema before migrating.",
          );
        statements = [];
      }
    }
    await db.batch([
      ...statements.map((s) => db.prepare(s)),
      db.prepare("INSERT INTO d1_migrations(name) VALUES(?)").bind(name),
    ]);
    console.log("Applied " + name);
  }
} finally {
  await mf.dispose();
}
