import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { crtSh, parseCrtSh } from "./ct.ts";

const rows = [
  { id: 1, common_name: "example.com", name_value: "example.com\nwww.example.com", not_after: "2026-01-01T00:00:00" },
  { id: 2, common_name: "*.shop.example.com", name_value: "*.shop.example.com\nTEST-payments.example.com", not_after: "2026-12-01T00:00:00" },
  { id: 3, common_name: "www.example.com", name_value: "www.example.com\nexample-cdn.net", not_after: "2027-02-01T00:00:00" },
  { id: 4, name_value: "not a name\n10.0.0.1" },
  null,
];

describe("certificate transparency", () => {
  it("reads every name once, wildcards without their *., with the latest end", () => {
    const names = parseCrtSh(rows);
    expect(names.map((n) => n.name).sort()).toEqual(["example-cdn.net", "example.com", "shop.example.com", "test-payments.example.com", "www.example.com"]);
    expect(names.find((n) => n.name === "www.example.com")!.notAfter).toBe("2027-02-01T00:00:00");
    expect(() => parseCrtSh({ error: "x" })).toThrow(/not a list/);
  });

  it("asks crt.sh for the names under a domain, naming itself", async () => {
    const seen: Array<{ url: string; agent: string }> = [];
    const server = createServer((req, res) => {
      seen.push({ url: req.url!, agent: String(req.headers["user-agent"]) });
      if (req.url!.includes("down.example")) return res.writeHead(502).end();
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(rows));
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const source = crtSh(`http://127.0.0.1:${(server.address() as AddressInfo).port}/`, "OpenAsy-AttackSurface/test");
    expect((await source("example.com")).length).toBe(5);
    expect(new URL(seen[0]!.url, "http://x").searchParams.get("q")).toBe("%.example.com");
    expect(seen[0]!.agent).toBe("OpenAsy-AttackSurface/test");
    await expect(source("down.example")).rejects.toThrow(/answered 502/);
    server.close();
  });
});
