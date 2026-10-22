import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { openDb } from "./db.ts";

describe("openDb", () => {
  it("uses WAL and migrates once", () => {
    const path = join(mkdtempSync(join(tmpdir(), "supply-chain-")), "nested", "supply-chain.db");
    const first = openDb(path);
    expect(first.prepare("PRAGMA journal_mode").get()).toEqual({ journal_mode: "wal" });
    first.close();

    const second = openDb(path);
    expect(second.prepare("SELECT COUNT(*) AS n FROM schema_migrations").get()).toEqual({ n: 1 });
    second.close();
  });

  it("deletes an image's packages with it, and keeps one image per name and digest", () => {
    const db = openDb(":memory:");
    db.exec(`INSERT INTO images (id, name, digest, created_at, updated_at) VALUES ('i', 'ghcr.io/acme/app', 'sha256:a', 'now', 'now');
      INSERT INTO packages VALUES ('i', 'zlib', '1', NULL, 'Zlib')`);
    expect(() => db.exec("INSERT INTO images (id, name, digest, created_at, updated_at) VALUES ('j', 'ghcr.io/acme/app', 'sha256:a', 'now', 'now')")).toThrow();
    db.exec("DELETE FROM images");
    expect(db.prepare("SELECT COUNT(*) AS n FROM packages").get()).toEqual({ n: 0 });
  });
});
