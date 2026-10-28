// A scan with the real prober against servers on this machine; only DNS and certificate transparency are fakes.
import { createServer as createHttp } from "node:http";
import { createServer as createTcp, type AddressInfo, type Server } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createLimiter, createProber, type Prober } from "./probe.ts";
import { runScan } from "./scan.ts";
import { parseCidr } from "./scope.ts";
import { fakeDns } from "./test-app.ts";

const servers: Server[] = [];
let web = 0;
let redis = 0;

beforeAll(async () => {
  const listen = async (s: Server) => (servers.push(s), await new Promise<void>((r) => s.listen(0, "127.0.0.1", r)), (s.address() as AddressInfo).port);
  web = await listen(createHttp((_req, res) => res.writeHead(200, { "content-type": "text/html" }).end("<title>Jenkins</title>")));
  redis = await listen(createTcp(() => {}));
});
afterAll(() => servers.forEach((s) => s.close()));

const prober = createProber({ userAgent: "OpenAsy-AttackSurface/test", timeoutMs: 1000, bannerMs: 100 });
/** The real prober, with every target it is handed written down. */
function recording(): Prober & { targets: string[] } {
  const targets: string[] = [];
  const note = (t: { name: string | null; address: string; port: number }) => targets.push(`${t.name ?? "-"}@${t.address}:${t.port}`);
  return {
    targets,
    port: (t) => (note(t), prober.port(t)),
    tls: (t) => (note(t), prober.tls(t)),
    legacyTls: (t) => (note(t), prober.legacyTls(t)),
    http: (t, s) => (note(t), prober.http(t, s)),
  };
}

describe("a scan of servers on this machine", () => {
  it("finds what answers under the verified domain and leaves everything else alone", async () => {
    const dns = fakeDns({
      "example.com": { a: ["127.0.0.1"] },
      "ci.example.com": { a: ["127.0.0.1"] },
      "evil.example.net": { a: ["127.0.0.1"] },
      "meta.example.com": { a: ["169.254.169.254"] },
    });
    const p = recording();
    const snap = await runScan(
      // Loopback is let through here only, for the test's servers; a real install cannot set it.
      { domains: ["example.com"], ranges: [], allowPrivate: false, allowLoopback: true },
      {
        dns,
        ct: async () => [
          { name: "ci.example.com", notAfter: null },
          { name: "evil.example.net", notAfter: null },
          { name: "meta.example.com", notAfter: null },
        ],
        prober: p,
        limit: createLimiter(100, 5),
        ports: [web, redis],
      },
    );
    // Services come by name, then port; both ports are random, so either may be lower.
    const ports = [web, redis].sort((a, b) => a - b);
    expect(snap.services.map((s) => [s.asset, s.port])).toEqual([
      ...ports.map((port) => ["ci.example.com", port]),
      ...ports.map((port) => ["example.com", port]),
    ]);
    // An unknown port is only connected to; a name outside the domain is never looked up for addresses, let alone probed.
    expect(p.targets.every((t) => /^(ci\.)?example\.com@127\.0\.0\.1:/.test(t))).toBe(true);
    expect(dns.asked).not.toContain("evil.example.net");
    expect(snap.outside).toEqual([{ name: "evil.example.net", seenAs: "certificate", via: "example.com" }]);
    expect(snap.assets.find((a) => a.key === "meta.example.com")!.note).toMatch(/never probed/);
    // Two names on one address: each port is connected to once.
    expect(snap.probes).toBe(2);
  });

  it("never probes a range on a loopback address, whoever added it", async () => {
    const p = recording();
    const snap = await runScan(
      { domains: [], ranges: [parseCidr("127.0.0.1/32")], allowPrivate: false },
      { dns: fakeDns({}), ct: null, prober: p, limit: createLimiter(100, 5), ports: [web] },
    );
    expect(p.targets).toEqual([]);
    expect(snap.assets).toEqual([]);
  });
});
