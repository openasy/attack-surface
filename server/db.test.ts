import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { openDb } from "./db.ts";

describe("openDb", () => {
  it("uses WAL and migrates once", () => {
    const path = join(mkdtempSync(join(tmpdir(), "attack-surface-")), "nested", "attack-surface.db");
    const first = openDb(path);
    expect(first.prepare("PRAGMA journal_mode").get()).toEqual({ journal_mode: "wal" });
    first.close();
    const second = openDb(path);
    expect(second.prepare("SELECT COUNT(*) AS n FROM schema_migrations").get()).toEqual({ n: 1 });
    second.close();
  });

  it("keeps the audit log append-only", () => {
    const db = openDb(":memory:");
    db.prepare("INSERT INTO audit (at, actor, action, target) VALUES ('t', 'Olivia', 'range-added', '203.0.113.0/28')").run();
    expect(() => db.prepare("UPDATE audit SET actor = 'someone else'").run()).toThrow(/append-only/);
    expect(() => db.prepare("DELETE FROM audit").run()).toThrow(/append-only/);
  });
});
