import { describe, expect, it } from "vitest";
import { proof, testSurface, tls } from "./test-app.ts";

const DAY = 86_400_000;

describe("domains", () => {
  it("are scan roots only once their TXT record holds the token", async () => {
    const t = testSurface();
    const d = t.surface.createDomain({ name: "https://Example.com/" }, "Olivia");
    expect(d).toMatchObject({ name: "example.com", state: "pending", proof: { name: "_openasy-attack-surface.example.com", type: "TXT" } });
    expect(d.proof.value).toMatch(/^openasy-attack-surface-verification=[\w-]{32}$/);
    expect(() => t.surface.createDomain({ name: "example.com" }, "Olivia")).toThrow(/already added/);
    expect(() => t.surface.createDomain({ name: "com" }, "Olivia")).toThrow(/domain name/);

    // Pending: the scan reads the proof, finds none, and touches nothing.
    const first = await t.scan();
    expect(first).toMatchObject({ state: "done", roots: [], assets: 0, probes: 0 });
    expect(first.warnings).toContain("Nothing to scan: no verified domain and no range.");
    expect(t.prober.calls).toEqual([]);
    expect(t.ctAsked).toEqual([]);
    expect(t.surface.domain(d.id).error).toMatch(/No TXT record/);

    t.dns.zone[d.proof.name] = proof(d.proof.value);
    expect((await t.surface.verifyDomain(d.id, "Olivia")).state).toBe("verified");
  });

  it("are not scanned again when the record goes, until it is back", async () => {
    const t = testSurface();
    const d = await t.own("example.com");
    await t.scan();
    const probes = t.prober.calls.length;
    expect(probes).toBeGreaterThan(0);
    delete t.dns.zone[d.proof.name];
    const scan = await t.scan();
    expect(t.surface.domain(d.id).state).toBe("lost");
    expect(scan.probes).toBe(0);
    expect(t.prober.calls.length).toBe(probes);
    // What was found before stays as it was, not reported as gone.
    expect(t.surface.assets().length).toBeGreaterThan(0);
    expect(t.surface.audit().map((a) => a.action)).toContain("domain-lost");
  });

  it("take what was found under them when deleted", async () => {
    const t = testSurface();
    const d = await t.own("example.com");
    await t.scan();
    t.surface.deleteDomain(d.id, "Olivia");
    expect(t.surface.assets()).toEqual([]);
    expect(t.surface.exposures()).toEqual([]);
    expect(t.surface.audit()[0]).toMatchObject({ action: "domain-deleted", target: "example.com", actor: "Olivia" });
  });
});

describe("a scan", () => {
  it("finds names from DNS and certificate transparency, and probes only those under the verified domain", async () => {
    const t = testSurface();
    await t.own("example.com");
    const scan = await t.scan();
    expect(scan.state).toBe("done");
    expect(t.ctAsked).toEqual(["example.com"]);
    expect(t.surface.assets().map((a) => a.key)).toEqual([
      "docs-old.example.com",
      "example.com",
      "intranet.example.com",
      "mail.example.com",
      "staging-admin.example.com",
      "www.example.com",
    ]);
    // Names outside the domain are listed, and never probed.
    expect(t.surface.outside().map((o) => [o.name, o.seenAs])).toEqual([
      ["acme-docs.s3-website.example-cloud.net", "cname"],
      ["aspmx.l.google.com", "mx"],
      ["ns1.dnsprovider.net", "ns"],
      ["partner-portal.com", "certificate"],
    ]);
    const touched = new Set(t.prober.calls.map((c) => c.name));
    expect([...touched].every((n) => n === "example.com" || n!.endsWith(".example.com"))).toBe(true);
    // A private address in public DNS is noted and not probed; a name that resolves to nothing is not an asset.
    expect(t.prober.calls.some((c) => c.address === "10.0.4.2")).toBe(false);
    expect(t.surface.asset("intranet.example.com").note).toMatch(/private address/);
    expect(t.surface.assets().some((a) => a.key === "old.example.com")).toBe(false);
    expect(t.surface.asset("staging-admin.example.com").ports).toEqual([22, 9200]);
  });

  it("connects once to an address and port, however many names point there", async () => {
    const t = testSurface();
    await t.own("example.com");
    await t.scan();
    const ports = t.prober.calls.filter((c) => c.kind === "port" && c.address === "198.51.100.10" && c.port === 443);
    expect(ports.length).toBe(1);
    // TLS and HTTP are per name, since a server answers each name with its own certificate and site.
    expect(
      t.prober.calls
        .filter((c) => c.kind === "tls" && c.address === "198.51.100.10")
        .map((c) => c.name)
        .sort(),
    ).toEqual(["example.com", "www.example.com"]);
  });

  it("finds exposures in what answered", async () => {
    const t = testSurface();
    await t.own("example.com");
    await t.scan();
    const found = t.surface.exposures().map((e) => [e.rule, e.asset, e.port]);
    expect(found).toContainEqual(["database-exposed", "staging-admin.example.com", 9200]);
    expect(found).toContainEqual(["dangling-cname", "docs-old.example.com", null]);
    expect(found).toContainEqual(["private-address", "intranet.example.com", null]);
    expect(found).toContainEqual(["ssh-exposed", "staging-admin.example.com", 22]);
    expect(found).not.toContainEqual(["spf-missing", "example.com", null]);
    expect(t.surface.exposures()[0]!.severity).toBe("high");
  });

  it("never runs two at once", async () => {
    const t = testSurface();
    const { done } = t.surface.startScan("manual", "Olivia");
    expect(() => t.surface.startScan("manual", "Olivia")).toThrow(/already running/);
    await done;
    expect(() => t.surface.startScan("manual", "Olivia")).not.toThrow();
  });

  it("is due once there is a root, and then once a day or when the roots change", async () => {
    const t = testSurface({ scanHours: 24 });
    expect(t.surface.due()).toBe(false);
    await t.own("example.com");
    expect(t.surface.due()).toBe(true);
    await t.scan();
    expect(t.surface.due()).toBe(false);
    t.later(23 * 3_600_000);
    t.surface.createRange({ cidr: "203.0.113.56/30", reason: "the staging servers at our provider" }, "Olivia");
    expect(t.surface.due()).toBe(true);
    await t.scan();
    t.later(24 * 3_600_000);
    expect(t.surface.due()).toBe(true);
  });
});

describe("changes", () => {
  it("are what appeared, went and changed since the last scan", async () => {
    const t = testSurface();
    await t.own("example.com");
    const first = await t.scan();
    expect(t.surface.changes({ scan: first.id }).filter((c) => c.subject === "asset" && c.kind === "added").length).toBe(6);

    t.later(DAY);
    // A new subdomain appears in the logs and answers on 8080... on a port in the list: 3389.
    t.ctNames["example.com"]!.push({ name: "test-payments.example.com", notAfter: null });
    t.dns.zone["test-payments.example.com"] = { a: ["203.0.113.90"] };
    t.prober.open["203.0.113.90:3389"] = {};
    // Elasticsearch is closed, mail moves, and the certificate is replaced.
    delete t.prober.open["203.0.113.57:9200"];
    t.dns.zone["mail.example.com"] = { a: ["198.51.100.13"] };
    t.prober.open["198.51.100.13:25"] = { banner: "220 mail.example.com ESMTP" };
    t.prober.open["198.51.100.10:443"]!.tls = tls({ fingerprint: "b".repeat(64), issuer: "E7" });
    delete t.dns.zone["docs-old.example.com"];

    const second = await t.scan();
    const seen = t.surface.changes({ scan: second.id }).map((c) => [c.kind, c.subject, c.asset, c.port, c.what]);
    expect(seen).toContainEqual(["added", "asset", "test-payments.example.com", null, "New host"]);
    expect(seen).toContainEqual(["added", "service", "test-payments.example.com", 3389, "Port 3389/rdp open"]);
    expect(seen).toContainEqual(["added", "exposure", "test-payments.example.com", 3389, "Remote Desktop (RDP) open to the internet"]);
    expect(seen).toContainEqual(["removed", "service", "staging-admin.example.com", 9200, "Port 9200/elasticsearch closed"]);
    expect(seen).toContainEqual(["removed", "exposure", "staging-admin.example.com", 9200, "Resolved: Elasticsearch open to the internet"]);
    expect(seen).toContainEqual(["changed", "asset", "mail.example.com", null, "Addresses changed"]);
    expect(seen).toContainEqual(["changed", "certificate", "www.example.com", 443, "Certificate replaced"]);
    expect(seen).toContainEqual(["removed", "asset", "docs-old.example.com", null, "Host no longer found"]);
    expect(t.surface.assets({ state: "gone" }).map((a) => a.key)).toEqual(["docs-old.example.com"]);
    expect(second.changes).toBe(seen.length);
  });

  it("report a certificate each time it crosses a threshold, not every scan", async () => {
    const t = testSurface();
    t.prober.open["198.51.100.10:443"]!.tls = tls({ notAfter: new Date(t.now() + 40 * DAY).toISOString() });
    await t.own("example.com");
    await t.scan();
    const expiring = () => t.surface.changes({ days: "400" }).filter((c) => c.subject === "certificate");
    expect(expiring()).toEqual([]);
    t.later(11 * DAY); // 29 days left: past 30
    await t.scan();
    expect(expiring().map((c) => [c.what, c.severity])).toEqual([
      ["Certificate expires in 29 days", "medium"],
      ["Certificate expires in 29 days", "medium"],
    ]);
    t.later(DAY);
    await t.scan();
    expect(expiring().length).toBe(2);
    t.later(23 * DAY); // 5 days left: past 14 and 7 at once, reported once, for the tighter one
    await t.scan();
    expect(
      expiring()
        .slice(0, 2)
        .map((c) => [c.what, c.severity]),
    ).toEqual([
      ["Certificate expires in 5 days", "high"],
      ["Certificate expires in 5 days", "high"],
    ]);
    expect(t.surface.certificates()[0]).toMatchObject({ state: "critical", daysLeft: 5, places: [{ asset: "example.com" }, { asset: "www.example.com" }] });
  });

  it("are acknowledged by name, once", async () => {
    const t = testSurface();
    await t.own("example.com");
    await t.scan();
    const [c] = t.surface.changes();
    expect(t.surface.acknowledge(String(c!.id), "Olivia")).toMatchObject({ acknowledgedBy: "Olivia" });
    expect(t.surface.acknowledge(String(c!.id), "Mallory").acknowledgedBy).toBe("Olivia");
    expect(() => t.surface.acknowledge("nope", "Olivia")).toThrow(/does not exist/);
    expect(() => t.surface.changes({ days: "0" })).toThrow(/days/);
  });
});

describe("ranges", () => {
  it("are added by name with a reason, which the audit log keeps", () => {
    const t = testSurface();
    expect(() => t.surface.createRange({ cidr: "203.0.113.0/28" }, "Olivia")).toThrow(/reason/);
    const r = t.surface.createRange({ cidr: "203.0.113.0/28", reason: "Hetzner contract 4471, office uplink" }, "Olivia");
    expect(r).toMatchObject({ cidr: "203.0.113.0/28", addresses: 16, createdBy: "Olivia" });
    expect(t.surface.audit()[0]).toMatchObject({
      action: "range-added",
      target: "203.0.113.0/28",
      detail: "Hetzner contract 4471, office uplink",
      actor: "Olivia",
    });
    expect(() => t.surface.createRange({ cidr: "203.0.113.8/29", reason: "the same addresses again" }, "Olivia")).toThrow(/overlaps/);
    expect(() => t.surface.createRange({ cidr: "203.0.112.0/23", reason: "a much larger network" }, "Olivia")).toThrow(/at most 256/);
  });

  it("refuse private addresses unless the install allows them, and never loopback or metadata", () => {
    const t = testSurface();
    const reason = "the office network, for the lab";
    expect(() => t.surface.createRange({ cidr: "10.0.0.0/24", reason }, "Olivia")).toThrow(/private address/);
    expect(() => t.surface.createRange({ cidr: "127.0.0.0/24", reason }, "Olivia")).toThrow(/never probed/);
    const lab = testSurface({ allowPrivate: true });
    expect(lab.surface.createRange({ cidr: "10.0.0.0/24", reason }, "Olivia").cidr).toBe("10.0.0.0/24");
    expect(() => lab.surface.createRange({ cidr: "169.254.169.254/32", reason }, "Olivia")).toThrow(/never probed/);
  });

  it("are probed address by address, and an address is an asset only when something answers", async () => {
    const t = testSurface();
    t.surface.createRange({ cidr: "203.0.113.56/30", reason: "the staging servers at our provider" }, "Olivia");
    const scan = await t.scan();
    expect(new Set(t.prober.calls.map((c) => c.address))).toEqual(new Set(["203.0.113.56", "203.0.113.57", "203.0.113.58", "203.0.113.59"]));
    expect(t.prober.calls.every((c) => c.name === null)).toBe(true);
    expect(t.surface.assets().map((a) => [a.key, a.kind, a.root])).toEqual([["203.0.113.57", "address", "203.0.113.56/30"]]);
    expect(scan.probes).toBe(4 * 6 + 1);
  });
});
