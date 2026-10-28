import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { OPENAPI } from "../scripts/openapi.ts";
import { ADMIN_TOKEN, proof, startApp } from "./test-app.ts";

// Contract tests (ADR 0024): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "attack-surface-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let base: string;
const covered = new Set<string>();

beforeAll(async () => {
  app = await startApp({ version, openapi: spec, docsDir });
  base = app.base;
});

afterAll(() => app.close());

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  // A response is either inline or a $ref to components/responses; build the JSON pointer to its schema either way.
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared
    ? `openapi#/components/responses/${shared}`
    : `openapi#/paths/${path.replaceAll("/", "~1")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();

  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body };
}

const auth = (token: string, body?: string, type = "application/json") => ({
  headers: { authorization: `Bearer ${token}`, "content-type": type },
  ...(body !== undefined && { body }),
});
const admin = (body?: unknown) => auth(ADMIN_TOKEN, body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body));

describe("openapi.json", () => {
  it("is what scripts/openapi.ts writes", () => {
    expect(spec).toEqual(JSON.parse(JSON.stringify(OPENAPI)));
  });

  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    // Attack Surface's own operations, then sign-in from @openasy/auth (tested against its description in that package).
    expect(Object.keys(served.paths).filter((p) => !p.startsWith("/api/v1/auth/"))).toEqual(Object.keys(spec.paths));
    expect(served.paths["/api/v1/auth/login"]).toBeDefined();
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", () => {
  let domain = "";
  let range = "";
  const post = { method: "POST", ...admin() };

  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/api/v1/products", admin());
    await call("GET", "/api/v1/products", {});
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
    await call("GET", "/api/v1/summary", admin());
    await call("GET", "/api/v1/summary", {});
  });

  it("roots", async () => {
    domain = ((await call("POST", "/api/v1/domains", admin({ name: "example.com" }))).body as { id: string }).id;
    await call("POST", "/api/v1/domains", admin({ name: "example.com" }));
    await call("POST", "/api/v1/domains", admin({ name: "not a domain" }));
    await call("POST", "/api/v1/domains", admin("nope"));
    await call("POST", "/api/v1/domains", { method: "POST" });
    await call("GET", "/api/v1/domains", admin());
    await call("GET", "/api/v1/domains", {});
    const one = "/api/v1/domains/{id}";
    await call("GET", one, admin(), `/api/v1/domains/${domain}`);
    await call("GET", one, admin(), "/api/v1/domains/missing");
    await call("GET", one, {}, `/api/v1/domains/${domain}`);
    const verify = "/api/v1/domains/{id}/verify";
    await call("POST", verify, post, `/api/v1/domains/${domain}/verify`);
    const d = app.surface.domain(domain);
    app.dns.zone[d.proof.name] = proof(d.proof.value);
    await call("POST", verify, post, `/api/v1/domains/${domain}/verify`);
    await call("POST", verify, post, "/api/v1/domains/missing/verify");
    await call("POST", verify, { method: "POST" }, `/api/v1/domains/${domain}/verify`);
    const other = ((await call("POST", "/api/v1/domains", admin({ name: "example.org" }))).body as { id: string }).id;
    await call("DELETE", one, admin(), `/api/v1/domains/${other}`);
    await call("DELETE", one, admin(), "/api/v1/domains/missing");
    await call("DELETE", one, { method: "DELETE" }, `/api/v1/domains/${other}`);

    const reason = "the staging servers at our provider";
    range = ((await call("POST", "/api/v1/ranges", admin({ cidr: "203.0.113.56/30", reason }))).body as { id: string }).id;
    await call("POST", "/api/v1/ranges", admin({ cidr: "203.0.113.56/30", reason }));
    await call("POST", "/api/v1/ranges", admin({ cidr: "10.0.0.0/24", reason }));
    await call("POST", "/api/v1/ranges", admin("nope"));
    await call("POST", "/api/v1/ranges", { method: "POST" });
    await call("GET", "/api/v1/ranges", admin());
    await call("GET", "/api/v1/ranges", {});
    const extra = ((await call("POST", "/api/v1/ranges", admin({ cidr: "198.51.100.0/30", reason }))).body as { id: string }).id;
    await call("DELETE", "/api/v1/ranges/{id}", admin(), `/api/v1/ranges/${extra}`);
    await call("DELETE", "/api/v1/ranges/{id}", admin(), "/api/v1/ranges/missing");
    await call("DELETE", "/api/v1/ranges/{id}", { method: "DELETE" }, `/api/v1/ranges/${range}`);
  });

  it("scans and what they find", async () => {
    const scan = ((await call("POST", "/api/v1/scans", post)).body as { id: string }).id;
    await call("POST", "/api/v1/scans", post);
    await call("POST", "/api/v1/scans", { method: "POST" });
    await call("GET", "/api/v1/scans/{id}", admin(), `/api/v1/scans/${scan}`);
    await app.surface.idle();
    await call("GET", "/api/v1/scans", admin());
    await call("GET", "/api/v1/scans", {});
    await call("GET", "/api/v1/scans/{id}", admin(), `/api/v1/scans/${scan}`);
    await call("GET", "/api/v1/scans/{id}", admin(), "/api/v1/scans/missing");
    await call("GET", "/api/v1/scans/{id}", {}, `/api/v1/scans/${scan}`);
    await call("GET", "/api/v1/summary", admin());

    await call("GET", "/api/v1/assets", admin());
    await call("GET", "/api/v1/assets", admin(), "/api/v1/assets?state=all&q=example");
    await call("GET", "/api/v1/assets", admin(), "/api/v1/assets?state=nope");
    await call("GET", "/api/v1/assets", {});
    const asset = "/api/v1/assets/{key}";
    await call("GET", asset, admin(), "/api/v1/assets/www.example.com");
    await call("GET", asset, admin(), "/api/v1/assets/203.0.113.57");
    await call("GET", asset, admin(), "/api/v1/assets/missing.example.com");
    await call("GET", asset, {}, "/api/v1/assets/www.example.com");
    await call("GET", "/api/v1/outside", admin());
    await call("GET", "/api/v1/outside", {});
    await call("GET", "/api/v1/exposures", admin());
    await call("GET", "/api/v1/exposures", admin(), "/api/v1/exposures?state=all&severity=high");
    await call("GET", "/api/v1/exposures", admin(), "/api/v1/exposures?severity=dire");
    await call("GET", "/api/v1/exposures", {});
    await call("GET", "/api/v1/certificates", admin());
    await call("GET", "/api/v1/certificates", {});

    const changes = (await call("GET", "/api/v1/changes", admin())).body as { changes: Array<{ id: number }> };
    await call("GET", "/api/v1/changes", admin(), `/api/v1/changes?scan=${scan}`);
    await call("GET", "/api/v1/changes", admin(), "/api/v1/changes?days=0");
    await call("GET", "/api/v1/changes", {});
    const ack = "/api/v1/changes/{id}/acknowledge";
    await call("POST", ack, post, `/api/v1/changes/${changes.changes[0]!.id}/acknowledge`);
    await call("POST", ack, post, "/api/v1/changes/999999/acknowledge");
    await call("POST", ack, { method: "POST" }, `/api/v1/changes/${changes.changes[0]!.id}/acknowledge`);
    await call("GET", "/api/v1/audit", admin());
    await call("GET", "/api/v1/audit", {});
    await call("GET", "/metrics");
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
