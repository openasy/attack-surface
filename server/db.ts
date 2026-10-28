import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones.
const MIGRATIONS = [
  `-- A domain the organisation says is its own. It is a scan root only while its state is verified: the TXT record
   -- with its token was found at the last check (ADR 0067).
   CREATE TABLE domains (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL UNIQUE,
     token TEXT NOT NULL,
     state TEXT NOT NULL CHECK (state IN ('pending', 'verified', 'lost')),
     created_at TEXT NOT NULL,
     created_by TEXT NOT NULL,
     verified_at TEXT,
     checked_at TEXT,
     error TEXT,
     -- Its DNS records at the last scan, as JSON.
     records TEXT
   );
   -- Addresses an admin added, with the reason they gave, which is in the audit log too.
   CREATE TABLE ranges (
     id TEXT PRIMARY KEY,
     cidr TEXT NOT NULL UNIQUE,
     reason TEXT NOT NULL,
     created_at TEXT NOT NULL,
     created_by TEXT NOT NULL
   );
   CREATE TABLE scans (
     id TEXT PRIMARY KEY,
     started_at TEXT NOT NULL,
     finished_at TEXT,
     trigger TEXT NOT NULL CHECK (trigger IN ('schedule', 'manual')),
     started_by TEXT,
     state TEXT NOT NULL CHECK (state IN ('running', 'done', 'failed')),
     error TEXT,
     roots TEXT NOT NULL DEFAULT '[]',
     assets INTEGER NOT NULL DEFAULT 0,
     services INTEGER NOT NULL DEFAULT 0,
     exposures INTEGER NOT NULL DEFAULT 0,
     changes INTEGER NOT NULL DEFAULT 0,
     probes INTEGER NOT NULL DEFAULT 0,
     warnings TEXT NOT NULL DEFAULT '[]'
   );
   CREATE INDEX scans_started ON scans (started_at);
   -- What was found, as of the last scan of its root. gone_at is set when a scan of the root no longer finds it.
   CREATE TABLE assets (
     key TEXT PRIMARY KEY,
     kind TEXT NOT NULL CHECK (kind IN ('name', 'address')),
     root TEXT NOT NULL,
     addresses TEXT NOT NULL,
     cname TEXT,
     sources TEXT NOT NULL,
     probed TEXT,
     note TEXT,
     first_seen TEXT NOT NULL,
     last_seen TEXT NOT NULL,
     gone_at TEXT
   );
   CREATE INDEX assets_root ON assets (root);
   CREATE TABLE services (
     asset TEXT NOT NULL REFERENCES assets (key) ON DELETE CASCADE,
     port INTEGER NOT NULL,
     root TEXT NOT NULL,
     address TEXT NOT NULL,
     service TEXT NOT NULL,
     banner TEXT,
     tls TEXT,
     legacy_tls INTEGER,
     http TEXT,
     first_seen TEXT NOT NULL,
     last_seen TEXT NOT NULL,
     gone_at TEXT,
     PRIMARY KEY (asset, port)
   );
   CREATE INDEX services_root ON services (root);
   CREATE TABLE exposures (
     id TEXT PRIMARY KEY,
     rule TEXT NOT NULL,
     severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
     title TEXT NOT NULL,
     detail TEXT NOT NULL,
     asset TEXT NOT NULL,
     root TEXT NOT NULL,
     port INTEGER,
     first_seen TEXT NOT NULL,
     last_seen TEXT NOT NULL,
     resolved_at TEXT
   );
   CREATE INDEX exposures_root ON exposures (root);
   -- Names seen outside every verified domain: on a certificate, as a CNAME target, a mail or name server. Never probed.
   CREATE TABLE outside (
     name TEXT PRIMARY KEY,
     seen_as TEXT NOT NULL,
     via TEXT NOT NULL,
     root TEXT NOT NULL,
     first_seen TEXT NOT NULL,
     last_seen TEXT NOT NULL
   );
   -- What a scan found different from the one before: the main view.
   CREATE TABLE changes (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     scan_id TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
     at TEXT NOT NULL,
     kind TEXT NOT NULL CHECK (kind IN ('added', 'removed', 'changed')),
     subject TEXT NOT NULL CHECK (subject IN ('asset', 'service', 'exposure', 'certificate')),
     asset TEXT NOT NULL,
     port INTEGER,
     severity TEXT,
     what TEXT NOT NULL,
     before TEXT,
     after TEXT,
     acknowledged_at TEXT,
     acknowledged_by TEXT
   );
   CREATE INDEX changes_at ON changes (at);
   -- Every change to the roots and every scan started (ADR 0013). Rows are added, never changed or removed.
   CREATE TABLE audit (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     at TEXT NOT NULL,
     actor TEXT NOT NULL,
     action TEXT NOT NULL,
     target TEXT NOT NULL,
     detail TEXT NOT NULL DEFAULT ''
   );
   CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
   CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END`,
];

/** Opens the product's single SQLite file in WAL mode (ADR 0011) and migrates it forward. */
export function openDb(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number };
  for (let v = row.v; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]!);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(v + 1, new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  return db;
}
