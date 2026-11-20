import {
  integer,
  primaryKey,
  sqliteTable,
  text,
} from "drizzle-orm/sqlite-core";

export const changes = sqliteTable(
  "workspace_changes",
  {
    tenant: text("tenant").notNull(),
    kind: text("kind").notNull(),
    id: text("id").notNull(),
    version: integer("version").notNull(),
    payload: text("payload").notNull(),
    modified: text("modified").notNull(),
  },
  (t) => [primaryKey({ columns: [t.tenant, t.kind, t.id] })],
);

export const audit = sqliteTable("workspace_audit", {
  id: text("id").primaryKey(),
  tenant: text("tenant").notNull(),
  record: text("record").notNull(),
  actor: text("actor").notNull(),
  action: text("action").notNull(),
  at: text("at").notNull(),
  detail: text("detail").notNull(),
});

export const sessions = sqliteTable("demo_sessions", {
  id: text("id").primaryKey(),
  tenant: text("tenant").notNull(),
  role: text("role").notNull(),
  expires: integer("expires").notNull(),
});
