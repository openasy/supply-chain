import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones.
const MIGRATIONS = [
  `CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
   -- An image is a name and a digest. What CI says about it is kept as it was told: this product does not verify
   -- signatures or provenance itself (ADR 0043). The SBOM is kept compressed, so it can be downloaded again.
   CREATE TABLE images (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL,
     digest TEXT NOT NULL,
     sbom BLOB,
     sbom_format TEXT,
     sbom_at TEXT,
     signature_verified INTEGER,
     signature_identity TEXT,
     signature_issuer TEXT,
     signature_at TEXT,
     provenance_builder TEXT,
     provenance_repo TEXT,
     provenance_commit TEXT,
     provenance_level INTEGER,
     provenance_at TEXT,
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL,
     UNIQUE (name, digest)
   );
   -- Packages of every SBOM, so "which images contain this" is one query.
   CREATE TABLE packages (
     image_id TEXT NOT NULL REFERENCES images (id) ON DELETE CASCADE,
     name TEXT NOT NULL,
     version TEXT NOT NULL,
     purl TEXT,
     licence TEXT
   );
   CREATE INDEX packages_image ON packages (image_id);
   CREATE INDEX packages_name ON packages (name, version);
   -- A rule waived for one image name (every digest) or one digest, with a reason and an end.
   CREATE TABLE exceptions (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL,
     digest TEXT,
     rule TEXT NOT NULL CHECK (rule IN ('signature', 'sbom', 'provenance', 'licences', 'all')),
     reason TEXT NOT NULL,
     created_by TEXT,
     created_at TEXT NOT NULL,
     expires_at TEXT NOT NULL
   );
   CREATE INDEX exceptions_name ON exceptions (name)`,
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
