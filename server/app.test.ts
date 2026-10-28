import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { proof, startApp } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;
let as: Awaited<ReturnType<typeof app.roles>>;

beforeAll(async () => {
  app = await startApp({ version: "0.1.0" });
  as = await app.roles();
});
afterAll(() => app.close());

const post = (body?: unknown) => ({ method: "POST", ...(body !== undefined && { body: JSON.stringify(body) }) });

describe("roles", () => {
  it("let editors add and verify domains, and only admins delete them", async () => {
    expect((await as.viewer("/api/v1/domains", post({ name: "example.com" }))).status).toBe(403);
    const res = await as.editor("/api/v1/domains", post({ name: "example.com" }));
    expect(res.status).toBe(201);
    const d = (await res.json()) as { id: string; proof: { name: string; value: string } };
    app.dns.zone[d.proof.name] = proof(d.proof.value);
    expect(await (await as.editor(`/api/v1/domains/${d.id}/verify`, post())).json()).toMatchObject({ state: "verified" });
    expect((await as.editor(`/api/v1/domains/${d.id}`, { method: "DELETE" })).status).toBe(403);
  });

  it("let only admins add a range, with a reason the audit log keeps by name", async () => {
    const body = { cidr: "203.0.113.56/30", reason: "the staging servers at our provider" };
    expect((await as.editor("/api/v1/ranges", post(body))).status).toBe(403);
    expect((await as.admin("/api/v1/ranges", post({ cidr: body.cidr }))).status).toBe(422);
    expect((await as.admin("/api/v1/ranges", post(body))).status).toBe(201);
    expect((await as.editor("/api/v1/audit")).status).toBe(403);
    const { entries } = (await (await as.admin("/api/v1/audit")).json()) as { entries: Array<Record<string, string>> };
    expect(entries[0]).toMatchObject({ action: "range-added", target: "203.0.113.56/30", detail: body.reason, actor: "API token admin" });
  });

  it("let editors scan and acknowledge, and viewers only look", async () => {
    expect((await as.viewer("/api/v1/scans", post())).status).toBe(403);
    expect((await as.editor("/api/v1/scans", post())).status).toBe(202);
    await app.surface.idle();
    const { changes } = (await (await as.viewer("/api/v1/changes")).json()) as { changes: Array<{ id: number }> };
    expect(changes.length).toBeGreaterThan(0);
    expect((await as.viewer(`/api/v1/changes/${changes[0]!.id}/acknowledge`, post())).status).toBe(403);
    expect(await (await as.editor(`/api/v1/changes/${changes[0]!.id}/acknowledge`, post())).json()).toMatchObject({ acknowledgedBy: "API token editor" });
  });
});

describe("the product", () => {
  it("names itself, and has metrics for Prometheus with what is exposed", async () => {
    expect(await (await fetch(`${app.base}/api/v1/version`)).json()).toEqual({ product: "attack-surface", version: "0.1.0" });
    const metrics = await (await fetch(`${app.base}/metrics`)).text();
    expect(metrics).toContain('openasy_build_info{product="attack-surface",version="0.1.0"} 1');
    expect(metrics).toContain('openasy_attack_surface_domains{state="verified"} 1');
    expect(metrics).toContain('openasy_attack_surface_exposures{severity="high"} 3');
    expect(metrics).toContain("openasy_attack_surface_last_scan_success 1");
    expect(metrics).toMatch(/openasy_attack_surface_assets \d+/);
  });

  it("sends the headers that keep the pages in their own frame and origin", async () => {
    const res = await fetch(`${app.base}/api/v1/version`);
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'self'");
  });
});
