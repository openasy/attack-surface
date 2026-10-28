// Writes openapi.json (ADR 0014, 0024). Run `node scripts/openapi.ts` after changing the API; a test fails when the
// file is out of date. Sign-in routes come from @openasy/auth and are merged in when the description is served.
import { writeFileSync } from "node:fs";

type S = Record<string, unknown>;
const ref = (n: string) => ({ $ref: `#/components/schemas/${n}` });
const str = { type: "string" };
const int = { type: "integer" };
const bool = { type: "boolean" };
const dt = { type: "string", format: "date-time" };
const nul = (s: S) => ({ anyOf: [s, { type: "null" }] });
const arr = (s: S) => ({ type: "array", items: s });
const obj = (properties: Record<string, S>, required = Object.keys(properties)) => ({ type: "object", required, properties });
const map = (s: S = str) => ({ type: "object", additionalProperties: s });

const problem = { $ref: "#/components/responses/Problem" };
const ok = (schema: S, description = "OK") => ({ description, content: { "application/json": { schema } } });
const VIEWER = [{ session: [] }, { apiToken: [] }, { adminToken: [] }];
const id = (what: string) => [{ name: "id", in: "path", required: true, description: `The ${what}'s id.`, schema: str }];

/** An operation that needs a role (ADR 0003), with the refusals every such operation can answer. */
function op(role: "viewer" | "editor" | "admin", o: S & { responses: Record<string, unknown> }) {
  return {
    ...o,
    security: VIEWER,
    "x-openasy-role": role,
    description: [`Needs the ${role} role.`, o.description].filter(Boolean).join(" "),
    responses: { ...o.responses, "401": problem, "403": problem, "503": problem },
  };
}

const SEVERITY = { type: "string", enum: ["critical", "high", "medium", "low", "info"] };

const Tls = obj({
  fingerprint: { type: "string", description: "SHA-256 of the certificate, hex." },
  subject: nul(str),
  issuer: nul(str),
  sans: arr(str),
  notBefore: dt,
  notAfter: dt,
  keyType: nul(str),
  keyBits: nul(int),
  protocol: nul({ type: "string", examples: ["TLSv1.3"] }),
  trusted: { type: "boolean", description: "Whether the system's roots trust the chain." },
  trustError: nul(str),
  nameMatches: { type: "boolean", description: "Whether the certificate is for the name connected to." },
  selfSigned: bool,
});

const Http = obj({
  status: int,
  headers: { ...map(), description: "The headers the checks read, lower case: server, location, content-type and the security headers." },
  title: nul(str),
  login: { type: "boolean", description: "The page has a password field." },
});

const schemas: Record<string, S> = {
  Problem: obj(
    {
      type: { type: "string", format: "uri" },
      title: str,
      status: int,
      code: {
        type: "string",
        enum: [
          "invalid-token",
          "invalid-json",
          "invalid-body",
          "conflict",
          "not-found",
          "internal-error",
          "unauthenticated",
          "invalid-credentials",
          "mfa-required",
          "mfa-setup-required",
          "forbidden",
          "cross-site",
          "rate-limited",
        ],
        description: "Stable; match on this.",
      },
      detail: str,
    },
    ["type", "title", "status", "code"],
  ),
  Status: obj({ status: str }),
  Version: obj({ product: { const: "attack-surface" }, version: str }),
  ProductLink: obj({
    id: { type: "string", description: "The product, as OpenAsy names it.", examples: ["dast"] },
    url: { type: "string", format: "uri", description: "The address people open it at.", examples: ["https://dast.example.com"] },
  }),
  ProductList: obj({ products: arr(ref("ProductLink")) }),
  DomainRecords: obj({
    a: arr(str),
    aaaa: arr(str),
    mx: arr(str),
    ns: arr(str),
    spf: nul(str),
    dmarc: nul(str),
    caa: arr(str),
  }),
  Domain: obj({
    id: str,
    name: { type: "string", examples: ["example.com"] },
    state: {
      type: "string",
      enum: ["pending", "verified", "lost"],
      description: "Only a verified domain is scanned. lost: it was verified, and its record was gone at the last check.",
    },
    proof: {
      ...obj({ name: { type: "string", examples: ["_openasy-attack-surface.example.com"] }, type: { const: "TXT" }, value: str }),
      description: "The TXT record the domain's owner publishes to prove it.",
    },
    createdAt: dt,
    createdBy: str,
    verifiedAt: nul(dt),
    checkedAt: nul(dt),
    error: nul({ type: "string", description: "Why the last check did not find the record." }),
    records: nul(ref("DomainRecords")),
    assets: { type: "integer", description: "Assets found under it." },
  }),
  DomainList: obj({ domains: arr(ref("Domain")) }),
  NewDomain: obj({ name: { type: "string", examples: ["example.com"] } }),
  Range: obj({
    id: str,
    cidr: { type: "string", examples: ["203.0.113.0/28"] },
    addresses: int,
    reason: str,
    createdAt: dt,
    createdBy: str,
    assets: int,
  }),
  RangeList: obj({ ranges: arr(ref("Range")) }),
  NewRange: obj({
    cidr: { type: "string", description: "An address or a range in CIDR notation, at most 256 addresses (a /24 or a /120).", examples: ["203.0.113.0/28"] },
    reason: { type: "string", minLength: 10, maxLength: 500, description: "Why the addresses are the organisation's. Kept in the audit log." },
  }),
  Scan: obj({
    id: str,
    startedAt: dt,
    finishedAt: nul(dt),
    trigger: { type: "string", enum: ["schedule", "manual"] },
    startedBy: nul(str),
    state: { type: "string", enum: ["running", "done", "failed"] },
    error: nul(str),
    roots: { ...arr(str), description: "The verified domains and ranges it scanned." },
    assets: int,
    services: int,
    exposures: int,
    changes: int,
    probes: { type: "integer", description: "Connections made." },
    warnings: arr(str),
  }),
  ScanList: obj({ scans: arr(ref("Scan")) }),
  Tls,
  Http,
  Service: obj({
    port: int,
    service: { type: "string", description: "What usually answers on the port; not fingerprinted." },
    address: str,
    banner: nul({ type: "string", description: "What the server sent first, unasked." }),
    tls: nul(ref("Tls")),
    legacyTls: nul({ type: "boolean", description: "TLS 1.0 or 1.1 is still taken." }),
    http: nul(ref("Http")),
    firstSeen: dt,
    lastSeen: dt,
    goneAt: nul(dt),
  }),
  Asset: obj({
    key: { type: "string", description: "The host name, or the address for one found in a range." },
    kind: { type: "string", enum: ["name", "address"] },
    root: { type: "string", description: "The verified domain or the range it is under." },
    addresses: arr(str),
    cname: nul(str),
    sources: arr({ type: "string", enum: ["dns", "certificate", "mx", "ns", "range"] }),
    probed: nul({ type: "string", description: "The address its ports were probed at." }),
    note: nul({ type: "string", description: "Why it was not probed." }),
    firstSeen: dt,
    lastSeen: dt,
    goneAt: nul(dt),
    ports: arr(int),
    exposures: int,
    worst: nul(SEVERITY),
  }),
  AssetList: obj({ assets: arr(ref("Asset")) }),
  AssetDetail: {
    allOf: [ref("Asset"), obj({ services: arr(ref("Service")), exposureList: arr(ref("Exposure")), changes: arr(ref("Change")) })],
  },
  Exposure: obj({
    id: { type: "string", description: "The same exposure across scans: its rule, asset and port." },
    rule: { type: "string", examples: ["database-exposed"] },
    severity: SEVERITY,
    title: str,
    detail: str,
    asset: str,
    root: str,
    port: nul(int),
    firstSeen: dt,
    lastSeen: dt,
    resolvedAt: nul(dt),
  }),
  ExposureList: obj({ exposures: arr(ref("Exposure")) }),
  Certificate: obj({
    fingerprint: str,
    subject: nul(str),
    issuer: nul(str),
    sans: arr(str),
    notBefore: dt,
    notAfter: dt,
    daysLeft: int,
    state: { type: "string", enum: ["expired", "critical", "expiring", "valid"] },
    trusted: bool,
    trustError: nul(str),
    selfSigned: bool,
    keyType: nul(str),
    keyBits: nul(int),
    protocols: arr(str),
    legacyTls: bool,
    places: arr(obj({ asset: str, port: int, nameMatches: bool })),
  }),
  CertificateList: obj({ certificates: arr(ref("Certificate")) }),
  Outside: obj({
    name: str,
    seenAs: { type: "string", enum: ["certificate", "cname", "mx", "ns"] },
    via: { type: "string", description: "The verified domain or name it was seen with." },
    root: str,
    firstSeen: dt,
    lastSeen: dt,
  }),
  OutsideList: obj({ names: arr(ref("Outside")) }),
  Change: obj({
    id: int,
    scanId: str,
    at: dt,
    kind: { type: "string", enum: ["added", "removed", "changed"] },
    subject: { type: "string", enum: ["asset", "service", "exposure", "certificate"] },
    asset: str,
    port: nul(int),
    severity: nul(SEVERITY),
    what: str,
    before: nul(str),
    after: nul(str),
    acknowledgedAt: nul(dt),
    acknowledgedBy: nul(str),
  }),
  ChangeList: obj({ changes: arr(ref("Change")) }),
  AuditEntry: obj({ id: int, at: dt, actor: str, action: str, target: str, detail: str }),
  AuditList: obj({ entries: arr(ref("AuditEntry")) }),
  Summary: obj({
    assets: int,
    newAssets: { type: "integer", description: "Assets first seen in the last 7 days." },
    services: int,
    exposures: obj({ critical: int, high: int, medium: int, low: int, info: int, total: int }),
    certificates: obj({ total: int, expiring: int, expired: int }),
    unacknowledged: int,
    outside: int,
    domains: obj({ verified: int, pending: int, lost: int }),
    ranges: int,
    ports: arr(obj({ port: int, service: str, count: int })),
    lastScan: nul(ref("Scan")),
    scanning: bool,
    nextScanAt: dt,
    settings: {
      ...obj({
        scanHours: int,
        ratePerSecond: nul(int),
        ports: arr(int),
        certificateTransparency: bool,
        allowPrivate: bool,
        certWarnDays: int,
      }),
      description: "How scans run, set in the environment (ATTACK_SURFACE_*).",
    },
  }),
};

const assetKey = [{ name: "key", in: "path", required: true, description: "The host name or address.", schema: str }];

const spec = {
  openapi: "3.1.1",
  info: {
    title: "OpenAsy Attack Surface API",
    version: "0.1.0",
    summary: "What your organisation exposes to the internet, from the domains you have proven are yours, and what changed since the last scan.",
    description:
      "Every screen of Attack Surface uses this API, and so can your scripts (ADR 0014). Within `/api/v1` changes are additive only; anything removed is deprecated first (ADR 0024). Errors use Problem Details (RFC 9457).\n\nEvery operation takes the session of a signed-in person or an API token, and names the role it needs (`x-openasy-role`: viewer, editor, admin; ADR 0003). Only verified domains and ranges an admin added are ever probed: names found outside them are listed and left alone (ADR 0067).\n\nSign-in, members and API tokens are under `/api/v1/auth`, provided by [@openasy/auth](https://github.com/openasy/auth#routes).",
    license: { name: "AGPL-3.0-only", identifier: "AGPL-3.0-only" },
  },
  servers: [{ url: "/", description: "This Attack Surface" }],
  tags: [
    { name: "Roots", description: "Domains proven by a TXT record, and ranges an admin added: all that is ever scanned." },
    { name: "Scans", description: "Discovery from DNS and certificate transparency, then a light check of each host." },
    { name: "Findings", description: "Assets, their open ports, exposures and certificates, as of the last scan." },
    { name: "Changes", description: "What appeared, went or changed since the scan before." },
    { name: "Product", description: "Version, overview and audit log of this Attack Surface." },
  ],
  paths: {
    "/api/v1/domains": {
      get: op("viewer", { operationId: "listDomains", tags: ["Roots"], summary: "Domains", responses: { "200": ok(ref("DomainList")) } }),
      post: op("editor", {
        operationId: "createDomain",
        tags: ["Roots"],
        summary: "Add a domain",
        description: "It is pending until its TXT record is found; nothing under it is touched before.",
        requestBody: { required: true, content: { "application/json": { schema: ref("NewDomain") } } },
        responses: { "201": ok(ref("Domain"), "Added, with the record to publish."), "400": problem, "409": problem, "422": problem },
      }),
    },
    "/api/v1/domains/{id}": {
      get: op("viewer", {
        operationId: "getDomain",
        tags: ["Roots"],
        summary: "A domain",
        parameters: id("domain"),
        responses: { "200": ok(ref("Domain")), "404": problem },
      }),
      delete: op("admin", {
        operationId: "deleteDomain",
        tags: ["Roots"],
        summary: "Delete a domain",
        description: "What was found under it goes too; its changes stay as history.",
        parameters: id("domain"),
        responses: { "204": { description: "Deleted." }, "404": problem },
      }),
    },
    "/api/v1/domains/{id}/verify": {
      post: op("editor", {
        operationId: "verifyDomain",
        tags: ["Roots"],
        summary: "Look for the TXT record now",
        description: "Every scan looks again first, and stops scanning a domain whose record has gone.",
        parameters: id("domain"),
        responses: { "200": ok(ref("Domain"), "The domain, verified or with why not."), "404": problem },
      }),
    },
    "/api/v1/ranges": {
      get: op("viewer", { operationId: "listRanges", tags: ["Roots"], summary: "Address ranges", responses: { "200": ok(ref("RangeList")) } }),
      post: op("admin", {
        operationId: "createRange",
        tags: ["Roots"],
        summary: "Add an address range",
        description:
          "With a reason, kept in the audit log. Private addresses are refused unless the install allows them; loopback, link-local and multicast ones always are.",
        requestBody: { required: true, content: { "application/json": { schema: ref("NewRange") } } },
        responses: { "201": ok(ref("Range"), "Added."), "400": problem, "409": problem, "422": problem },
      }),
    },
    "/api/v1/ranges/{id}": {
      delete: op("admin", {
        operationId: "deleteRange",
        tags: ["Roots"],
        summary: "Delete an address range",
        parameters: id("range"),
        responses: { "204": { description: "Deleted." }, "404": problem },
      }),
    },
    "/api/v1/scans": {
      get: op("viewer", { operationId: "listScans", tags: ["Scans"], summary: "The last 50 scans", responses: { "200": ok(ref("ScanList")) } }),
      post: op("editor", {
        operationId: "startScan",
        tags: ["Scans"],
        summary: "Scan now",
        description: "It runs in the background; 409 while another one runs.",
        responses: { "202": ok(ref("Scan"), "Started."), "409": problem },
      }),
    },
    "/api/v1/scans/{id}": {
      get: op("viewer", {
        operationId: "getScan",
        tags: ["Scans"],
        summary: "A scan",
        parameters: id("scan"),
        responses: { "200": ok(ref("Scan")), "404": problem },
      }),
    },
    "/api/v1/assets": {
      get: op("viewer", {
        operationId: "listAssets",
        tags: ["Findings"],
        summary: "Assets",
        description: "Host names and addresses that answer, with their open ports.",
        parameters: [
          { name: "state", in: "query", schema: { type: "string", enum: ["present", "gone", "all"], default: "present" } },
          { name: "q", in: "query", description: "Part of the name or address.", schema: str },
        ],
        responses: { "200": ok(ref("AssetList")), "422": problem },
      }),
    },
    "/api/v1/assets/{key}": {
      get: op("viewer", {
        operationId: "getAsset",
        tags: ["Findings"],
        summary: "An asset",
        description: "With its services, exposures and changes.",
        parameters: assetKey,
        responses: { "200": ok(ref("AssetDetail")), "404": problem },
      }),
    },
    "/api/v1/outside": {
      get: op("viewer", {
        operationId: "listOutside",
        tags: ["Findings"],
        summary: "Names outside the verified domains",
        description: "Seen on a certificate, as a CNAME target, a mail or name server. Never probed.",
        responses: { "200": ok(ref("OutsideList")) },
      }),
    },
    "/api/v1/exposures": {
      get: op("viewer", {
        operationId: "listExposures",
        tags: ["Findings"],
        summary: "Exposures",
        description: "The worst first.",
        parameters: [
          { name: "state", in: "query", schema: { type: "string", enum: ["open", "resolved", "all"], default: "open" } },
          { name: "severity", in: "query", schema: SEVERITY },
        ],
        responses: { "200": ok(ref("ExposureList")), "422": problem },
      }),
    },
    "/api/v1/certificates": {
      get: op("viewer", {
        operationId: "listCertificates",
        tags: ["Findings"],
        summary: "Certificates presented",
        description: "Each once, with where it was seen, the soonest to end first.",
        responses: { "200": ok(ref("CertificateList")) },
      }),
    },
    "/api/v1/changes": {
      get: op("viewer", {
        operationId: "listChanges",
        tags: ["Changes"],
        summary: "Changes",
        description: "The newest first, at most 2000.",
        parameters: [
          { name: "days", in: "query", description: "How far back, 1 to 400 days.", schema: { type: "integer", default: 30 } },
          { name: "scan", in: "query", description: "Only those of one scan.", schema: str },
        ],
        responses: { "200": ok(ref("ChangeList")), "422": problem },
      }),
    },
    "/api/v1/changes/{id}/acknowledge": {
      post: op("editor", {
        operationId: "acknowledgeChange",
        tags: ["Changes"],
        summary: "Acknowledge a change",
        description: "Says someone has looked at it; a second time keeps the first.",
        parameters: id("change"),
        responses: { "200": ok(ref("Change")), "404": problem },
      }),
    },
    "/api/v1/audit": {
      get: op("admin", {
        operationId: "listAudit",
        tags: ["Product"],
        summary: "Audit log",
        description: "Domains and ranges added, verified, lost and deleted, and scans started, the newest 500. Append-only.",
        responses: { "200": ok(ref("AuditList")) },
      }),
    },
    "/api/v1/summary": {
      get: op("viewer", {
        operationId: "getSummary",
        tags: ["Product"],
        summary: "Overview",
        description: "Counts for the first screen.",
        responses: { "200": ok(ref("Summary")) },
      }),
    },
    "/api/v1/products": {
      get: op("viewer", {
        operationId: "listProducts",
        tags: ["Product"],
        summary: "Other products of this install",
        responses: { "200": ok(ref("ProductList"), "From OPENASY_PRODUCTS, for the product switcher.") },
      }),
    },
    "/api/v1/version": {
      get: { operationId: "getVersion", tags: ["Product"], summary: "Version", security: [], responses: { "200": ok(ref("Version"), "The running version.") } },
    },
    "/healthz": {
      get: {
        operationId: "liveness",
        tags: ["Product"],
        summary: "Liveness",
        security: [],
        responses: { "200": ok(ref("Status"), "The process is running.") },
      },
    },
    "/readyz": {
      get: {
        operationId: "readiness",
        tags: ["Product"],
        summary: "Readiness",
        description: "Ready while its SQLite file answers.",
        security: [],
        responses: { "200": ok(ref("Status"), "Ready to serve."), "503": ok(ref("Status"), "The database is unavailable.") },
      },
    },
    "/metrics": {
      get: {
        operationId: "metrics",
        tags: ["Product"],
        summary: "Prometheus metrics",
        security: [],
        responses: { "200": { description: "Metrics in the Prometheus text format.", content: { "text/plain": { schema: str } } } },
      },
    },
  },
  components: {
    securitySchemes: {
      session: {
        type: "apiKey",
        in: "cookie",
        name: "__Host-openasy-session",
        description:
          "The browser session after signing in (`openasy-session` when Attack Surface runs on plain http://localhost). Requests that change something must come from the Attack Surface origin.",
      },
      apiToken: {
        type: "http",
        scheme: "bearer",
        description: "An API token created under Settings → API tokens (`oa_attack-surface_...`): one role, always an expiry (ADR 0003).",
      },
      adminToken: {
        type: "http",
        scheme: "bearer",
        description:
          "Only when Attack Surface is started by its tests or a local script: one shared token with the admin role. A production install does not have it.",
      },
    },
    responses: { Problem: { description: "An error, as RFC 9457 Problem Details.", content: { "application/problem+json": { schema: ref("Problem") } } } },
    schemas,
  },
};

export const OPENAPI = spec;
if (import.meta.url === `file://${process.argv[1]}`) writeFileSync(new URL("../openapi.json", import.meta.url), JSON.stringify(spec, null, 2) + "\n");
