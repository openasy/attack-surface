// Attack Surface's records (ADR 0067): the roots, domains proven by a TXT record and ranges an admin added with a
// reason, the scans, and what the last scan of each root found, compared with the one before it.
import { randomBytes, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { CtSource } from "./ct.ts";
import { hasProof, proofName, proofValue, type Dns, type DomainRecords } from "./dns.ts";
import { log } from "./log.ts";
import type { HttpResult, Limiter, Prober, TlsResult } from "./probe.ts";
import { certDays, exposures as findExposures, type CertDays, type Exposure, type Severity } from "./rules.ts";
import { runScan, type ServiceObs, type Snapshot } from "./scan.ts";
import { addressRefusal, hostName, inCidr, parseCidr, type Cidr } from "./scope.ts";

export type ProblemCode = "invalid-token" | "invalid-json" | "invalid-body" | "not-found" | "conflict" | "internal-error";

export class SurfaceError extends Error {
  readonly status: number;
  readonly code: ProblemCode;
  constructor(status: number, code: ProblemCode, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
  }
}

const invalid = (detail: string) => new SurfaceError(422, "invalid-body", detail);
const notFound = (what: string) => new SurfaceError(404, "not-found", `${what} does not exist.`);

export interface SurfaceOptions {
  dns: Dns;
  ct: CtSource | null;
  prober: Prober;
  limit: Limiter;
  ports: number[];
  /** Private addresses may be probed and added as ranges (ATTACK_SURFACE_ALLOW_PRIVATE). */
  allowPrivate?: boolean;
  /** Only tests set it; see scope.ts. */
  allowLoopback?: boolean;
  scanHours?: number;
  /** ATTACK_SURFACE_RATE, for the Scans page; the limiter is what holds to it. */
  ratePerSecond?: number;
  certDays?: CertDays;
  maxNames?: number;
  clock?: () => number;
}

export type DomainState = "pending" | "verified" | "lost";

export interface Domain {
  id: string;
  name: string;
  state: DomainState;
  /** The TXT record that proves the domain is the organisation's. */
  proof: { name: string; type: "TXT"; value: string };
  createdAt: string;
  createdBy: string;
  verifiedAt: string | null;
  checkedAt: string | null;
  error: string | null;
  records: DomainRecords | null;
  assets: number;
}

export interface Range {
  id: string;
  cidr: string;
  addresses: number;
  reason: string;
  createdAt: string;
  createdBy: string;
  assets: number;
}

export interface Scan {
  id: string;
  startedAt: string;
  finishedAt: string | null;
  trigger: "schedule" | "manual";
  startedBy: string | null;
  state: "running" | "done" | "failed";
  error: string | null;
  roots: string[];
  assets: number;
  services: number;
  exposures: number;
  changes: number;
  probes: number;
  warnings: string[];
}

export interface Service {
  port: number;
  service: string;
  address: string;
  banner: string | null;
  tls: TlsResult | null;
  legacyTls: boolean | null;
  http: HttpResult | null;
  firstSeen: string;
  lastSeen: string;
  goneAt: string | null;
}

export interface Asset {
  key: string;
  kind: "name" | "address";
  root: string;
  addresses: string[];
  cname: string | null;
  sources: string[];
  probed: string | null;
  note: string | null;
  firstSeen: string;
  lastSeen: string;
  goneAt: string | null;
  ports: number[];
  exposures: number;
  worst: Severity | null;
}

export interface ExposureRow extends Exposure {
  firstSeen: string;
  lastSeen: string;
  resolvedAt: string | null;
}

export interface Change {
  id: number;
  scanId: string;
  at: string;
  kind: "added" | "removed" | "changed";
  subject: "asset" | "service" | "exposure" | "certificate";
  asset: string;
  port: number | null;
  severity: Severity | null;
  what: string;
  before: string | null;
  after: string | null;
  acknowledgedAt: string | null;
  acknowledgedBy: string | null;
}

export interface Certificate {
  fingerprint: string;
  subject: string | null;
  issuer: string | null;
  sans: string[];
  notBefore: string;
  notAfter: string;
  daysLeft: number;
  state: "expired" | "critical" | "expiring" | "valid";
  trusted: boolean;
  trustError: string | null;
  selfSigned: boolean;
  keyType: string | null;
  keyBits: number | null;
  protocols: string[];
  legacyTls: boolean;
  places: Array<{ asset: string; port: number; nameMatches: boolean }>;
}

export interface Outside {
  name: string;
  seenAs: "certificate" | "cname" | "mx" | "ns";
  via: string;
  root: string;
  firstSeen: string;
  lastSeen: string;
}

export interface AuditEntry {
  id: number;
  at: string;
  actor: string;
  action: string;
  target: string;
  detail: string;
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const DAY = 86_400_000;
const json = <T>(v: unknown, fallback: T): T => (typeof v === "string" ? (JSON.parse(v) as T) : fallback);
const text = (body: Record<string, unknown>, key: string) => (typeof body[key] === "string" ? (body[key] as string).trim() : "");

type Row = Record<string, unknown>;

export function createSurface(db: DatabaseSync, options: SurfaceOptions) {
  const clock = options.clock ?? Date.now;
  const now = () => new Date(clock()).toISOString();
  const days = options.certDays ?? certDays(undefined);
  const allowPrivate = options.allowPrivate ?? false;
  const scanHours = options.scanHours ?? 24;
  let running: Promise<void> | null = null;

  function audit(actor: string, action: string, target: string, detail = "") {
    db.prepare("INSERT INTO audit (at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)").run(now(), actor, action, target, detail);
    // Also on stdout, for SIEM to collect with the other products' audit events (ADR 0013).
    log("info", "audit", { action, target, by: actor, ...(detail && { detail }) });
  }

  // ------------------------------------------------------------ Roots

  const countAssets = (root: string) => (db.prepare("SELECT COUNT(*) AS n FROM assets WHERE root = ? AND gone_at IS NULL").get(root) as { n: number }).n;

  const toDomain = (r: Row): Domain => ({
    id: r.id as string,
    name: r.name as string,
    state: r.state as DomainState,
    proof: { name: proofName(r.name as string), type: "TXT", value: proofValue(r.token as string) },
    createdAt: r.created_at as string,
    createdBy: r.created_by as string,
    verifiedAt: (r.verified_at as string) ?? null,
    checkedAt: (r.checked_at as string) ?? null,
    error: (r.error as string) ?? null,
    records: json(r.records, null),
    assets: countAssets(r.name as string),
  });

  const domainRow = (id: string) => {
    const r = db.prepare("SELECT * FROM domains WHERE id = ?").get(id) as Row | undefined;
    if (!r) throw notFound("The domain");
    return r;
  };

  /** Checks the proof record now; a verified domain whose record has gone is lost, and is not scanned until it is back. */
  async function check(r: Row, actor: string): Promise<DomainState> {
    let found = false;
    let error: string | null = null;
    try {
      found = await hasProof(options.dns, r.name as string, r.token as string);
      if (!found) error = `No TXT record ${proofValue(r.token as string)} at ${proofName(r.name as string)}.`;
    } catch (err) {
      error = `${proofName(r.name as string)} could not be read: ${(err as Error).message}`;
    }
    const before = r.state as DomainState;
    const state: DomainState = found ? "verified" : before === "pending" ? "pending" : "lost";
    db.prepare("UPDATE domains SET state = ?, checked_at = ?, error = ?, verified_at = CASE WHEN ? THEN ? ELSE verified_at END WHERE id = ?").run(
      state,
      now(),
      error,
      found && before !== "verified" ? 1 : 0,
      now(),
      r.id as string,
    );
    if (state !== before) audit(actor, `domain-${state === "verified" ? "verified" : "lost"}`, r.name as string, error ?? "");
    return state;
  }

  const domains = () => (db.prepare("SELECT * FROM domains ORDER BY name").all() as Row[]).map(toDomain);

  function createDomain(body: Record<string, unknown>, actor: string): Domain {
    const name = hostName(
      text(body, "name")
        .replace(/^https?:\/\//, "")
        .replace(/\/.*$/, ""),
    );
    if (!name) throw invalid("name must be a domain name, such as example.com.");
    if (db.prepare("SELECT 1 FROM domains WHERE name = ?").get(name)) throw new SurfaceError(409, "conflict", `${name} is already added.`);
    const id = randomUUID();
    // The token is published in DNS by the owner; it proves control of the zone, and is not a secret.
    const token = randomBytes(24).toString("base64url");
    db.prepare("INSERT INTO domains (id, name, token, state, created_at, created_by) VALUES (?, ?, ?, 'pending', ?, ?)").run(id, name, token, now(), actor);
    audit(actor, "domain-added", name);
    return toDomain(domainRow(id));
  }

  async function verifyDomain(id: string, actor: string): Promise<Domain> {
    await check(domainRow(id), actor);
    return toDomain(domainRow(id));
  }

  /** Removes everything found under a root; the changes stay as history. */
  function forget(root: string) {
    for (const table of ["services", "exposures", "outside", "assets"]) db.prepare(`DELETE FROM ${table} WHERE root = ?`).run(root);
  }

  function deleteDomain(id: string, actor: string) {
    const r = domainRow(id);
    db.prepare("DELETE FROM domains WHERE id = ?").run(id);
    forget(r.name as string);
    audit(actor, "domain-deleted", r.name as string);
  }

  const toRange = (r: Row): Range => ({
    id: r.id as string,
    cidr: r.cidr as string,
    addresses: Number(parseCidr(r.cidr as string).size),
    reason: r.reason as string,
    createdAt: r.created_at as string,
    createdBy: r.created_by as string,
    assets: countAssets(r.cidr as string),
  });

  const ranges = () => (db.prepare("SELECT * FROM ranges ORDER BY cidr").all() as Row[]).map(toRange);

  function createRange(body: Record<string, unknown>, actor: string): Range {
    let range: Cidr;
    try {
      range = parseCidr(text(body, "cidr"));
    } catch (err) {
      throw invalid((err as Error).message);
    }
    const reason = text(body, "reason");
    if (reason.length < 10 || reason.length > 500)
      throw invalid("reason must say, in 10 to 500 characters, why these addresses are the organisation's, such as the provider and the contract.");
    // A range is at most a /24 or a /120, and every private or forbidden block is larger and aligned: its first
    // address says what the whole range is.
    const first = range.cidr.split("/")[0]!;
    const refusal = addressRefusal(first, { domains: [], ranges: [], allowPrivate });
    if (refusal) throw invalid(`${range.cidr} is ${refusal}.`);
    // Ranges are aligned blocks, so two overlap only when one holds the other's first address.
    for (const other of ranges()) {
      const o = parseCidr(other.cidr);
      if (inCidr(first, o) || inCidr(other.cidr.split("/")[0]!, range))
        throw new SurfaceError(409, "conflict", `${range.cidr} overlaps ${other.cidr}, which is already added.`);
    }
    const id = randomUUID();
    db.prepare("INSERT INTO ranges (id, cidr, reason, created_at, created_by) VALUES (?, ?, ?, ?, ?)").run(id, range.cidr, reason, now(), actor);
    audit(actor, "range-added", range.cidr, reason);
    return toRange(db.prepare("SELECT * FROM ranges WHERE id = ?").get(id) as Row);
  }

  function deleteRange(id: string, actor: string) {
    const r = db.prepare("SELECT * FROM ranges WHERE id = ?").get(id) as Row | undefined;
    if (!r) throw notFound("The range");
    db.prepare("DELETE FROM ranges WHERE id = ?").run(id);
    forget(r.cidr as string);
    audit(actor, "range-deleted", r.cidr as string);
  }

  // ------------------------------------------------------------ Scans

  const toScan = (r: Row): Scan => ({
    id: r.id as string,
    startedAt: r.started_at as string,
    finishedAt: (r.finished_at as string) ?? null,
    trigger: r.trigger as Scan["trigger"],
    startedBy: (r.started_by as string) ?? null,
    state: r.state as Scan["state"],
    error: (r.error as string) ?? null,
    roots: json(r.roots, []),
    assets: r.assets as number,
    services: r.services as number,
    exposures: r.exposures as number,
    changes: r.changes as number,
    probes: r.probes as number,
    warnings: json(r.warnings, []),
  });

  const scans = (limit = 50) => (db.prepare("SELECT * FROM scans ORDER BY started_at DESC, rowid DESC LIMIT ?").all(limit) as Row[]).map(toScan);

  function scanById(id: string): Scan {
    const r = db.prepare("SELECT * FROM scans WHERE id = ?").get(id) as Row | undefined;
    if (!r) throw notFound("The scan");
    return toScan(r);
  }

  const lastScan = () => scans(1)[0] ?? null;

  /** Starts a scan unless one runs. It goes on in the background; `done` settles when it has finished. */
  function startScan(trigger: Scan["trigger"], actor: string | null): { scan: Scan; done: Promise<void> } {
    if (running) throw new SurfaceError(409, "conflict", "A scan is already running.");
    const id = randomUUID();
    db.prepare("INSERT INTO scans (id, started_at, trigger, started_by, state) VALUES (?, ?, ?, ?, 'running')").run(id, now(), trigger, actor);
    if (actor) audit(actor, "scan-started", id);
    const done = scanNow(id, actor ?? "schedule")
      .catch((err: unknown) => {
        log("error", "scan failed", { scan: id, error: String(err) });
        db.prepare("UPDATE scans SET state = 'failed', finished_at = ?, error = ? WHERE id = ?").run(now(), String((err as Error).message ?? err), id);
      })
      .finally(() => (running = null));
    running = done;
    return { scan: scanById(id), done };
  }

  async function scanNow(id: string, actor: string) {
    // Every domain's proof is read again first: only those whose record is there now are scanned.
    for (const r of db.prepare("SELECT * FROM domains").all() as Row[]) await check(r, actor);
    const verified = (db.prepare("SELECT name FROM domains WHERE state = 'verified' ORDER BY name").all() as Array<{ name: string }>).map((r) => r.name);
    const cidrs = ranges().map((r) => parseCidr(r.cidr));
    const roots = [...verified, ...cidrs.map((c) => c.cidr)];
    db.prepare("UPDATE scans SET roots = ? WHERE id = ?").run(JSON.stringify(roots), id);
    const snap = await runScan(
      { domains: verified, ranges: cidrs, allowPrivate, allowLoopback: options.allowLoopback },
      { dns: options.dns, ct: options.ct, prober: options.prober, limit: options.limit, ports: options.ports, maxNames: options.maxNames },
    );
    if (!roots.length) snap.warnings.push("Nothing to scan: no verified domain and no range.");
    const found = findExposures(snap, clock(), days);
    const changes = apply(id, roots, snap, found);
    db.prepare(
      "UPDATE scans SET state = 'done', finished_at = ?, assets = ?, services = ?, exposures = ?, changes = ?, probes = ?, warnings = ? WHERE id = ?",
    ).run(now(), snap.assets.length, snap.services.length, found.length, changes, snap.probes, JSON.stringify(snap.warnings), id);
    log("info", "scan done", { scan: id, roots: roots.length, assets: snap.assets.length, services: snap.services.length, exposures: found.length, changes });
  }

  /** The tightest certificate threshold a date has crossed at a time, as an index into days.steps, or -1. */
  const step = (notAfter: string, at: number) => {
    const left = (Date.parse(notAfter) - at) / DAY;
    let crossed = -1;
    days.steps.forEach((d, i) => left <= d && (crossed = i));
    return crossed;
  };

  /** Writes a snapshot over the last state of its roots, and records what is different. Returns how many changes. */
  function apply(scanId: string, roots: string[], snap: Snapshot, found: Exposure[]): number {
    const at = now();
    const scanned = new Set(roots);
    let count = 0;
    const change = (
      c: Omit<Change, "id" | "scanId" | "at" | "acknowledgedAt" | "acknowledgedBy" | "port" | "severity" | "before" | "after"> & Partial<Change>,
    ) => {
      count++;
      db.prepare("INSERT INTO changes (scan_id, at, kind, subject, asset, port, severity, what, before, after) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(
        scanId,
        at,
        c.kind,
        c.subject,
        c.asset,
        c.port ?? null,
        c.severity ?? null,
        c.what,
        c.before ?? null,
        c.after ?? null,
      );
    };
    const live = (table: string) => (db.prepare(`SELECT * FROM ${table} WHERE gone_at IS NULL`).all() as Row[]).filter((r) => scanned.has(r.root as string));

    db.exec("BEGIN");
    try {
      // Assets.
      const before = new Map(live("assets").map((r) => [r.key as string, r]));
      for (const a of snap.assets) {
        const old = db.prepare("SELECT * FROM assets WHERE key = ?").get(a.key) as Row | undefined;
        const addresses = JSON.stringify(a.addresses);
        if (!old || old.gone_at) {
          change({
            kind: "added",
            subject: "asset",
            asset: a.key,
            what: a.kind === "name" ? "New host" : "New address answering",
            after: a.addresses.join(", ") || a.cname,
          });
        } else if (old.addresses !== addresses) {
          change({
            kind: "changed",
            subject: "asset",
            asset: a.key,
            what: "Addresses changed",
            before: json<string[]>(old.addresses, []).join(", "),
            after: a.addresses.join(", "),
          });
        }
        db.prepare(
          `INSERT INTO assets (key, kind, root, addresses, cname, sources, probed, note, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (key) DO UPDATE SET kind = excluded.kind, root = excluded.root, addresses = excluded.addresses, cname = excluded.cname,
             sources = excluded.sources, probed = excluded.probed, note = excluded.note, last_seen = excluded.last_seen, gone_at = NULL,
             first_seen = CASE WHEN assets.gone_at IS NULL THEN assets.first_seen ELSE excluded.first_seen END`,
        ).run(a.key, a.kind, a.root, addresses, a.cname, JSON.stringify(a.sources), a.probed, a.note, at, at);
        before.delete(a.key);
      }
      for (const key of before.keys()) {
        change({ kind: "removed", subject: "asset", asset: key, what: "Host no longer found" });
        db.prepare("UPDATE assets SET gone_at = ? WHERE key = ?").run(at, key);
        db.prepare("UPDATE services SET gone_at = ? WHERE asset = ? AND gone_at IS NULL").run(at, key);
      }

      // Services, and the certificates they present.
      const oldServices = new Map(live("services").map((r) => [`${r.asset}|${r.port}`, r]));
      const lastAt = Date.parse((db.prepare("SELECT MAX(finished_at) AS t FROM scans WHERE state = 'done'").get() as { t: string | null }).t ?? at);
      for (const s of snap.services) {
        const k = `${s.asset}|${s.port}`;
        const old = oldServices.get(k);
        const label = `${s.port}/${s.service}`;
        if (!old)
          change({
            kind: "added",
            subject: "service",
            asset: s.asset,
            port: s.port,
            what: `Port ${label} open`,
            after: s.banner ?? s.http?.headers.server ?? null,
          });
        const was = json<TlsResult | null>(old?.tls, null);
        if (old && s.tls && was && was.fingerprint !== s.tls.fingerprint) {
          change({
            kind: "changed",
            subject: "certificate",
            asset: s.asset,
            port: s.port,
            what: "Certificate replaced",
            before: `${was.issuer ?? "?"}, until ${was.notAfter.slice(0, 10)}`,
            after: `${s.tls.issuer ?? "?"}, until ${s.tls.notAfter.slice(0, 10)}`,
          });
        } else if (s.tls) {
          const crossed = step(s.tls.notAfter, clock());
          const then = was ? step(was.notAfter, lastAt) : -1;
          if (crossed > then && crossed >= 0) {
            const left = Math.ceil((Date.parse(s.tls.notAfter) - clock()) / DAY);
            change({
              kind: "changed",
              subject: "certificate",
              asset: s.asset,
              port: s.port,
              severity: left <= 0 ? "critical" : left <= days.critical ? "high" : "medium",
              what: left <= 0 ? "Certificate expired" : `Certificate expires in ${left} day${left === 1 ? "" : "s"}`,
              after: s.tls.notAfter.slice(0, 10),
            });
          }
        }
        upsertService(s, at);
        oldServices.delete(k);
      }
      // A port of a host that is gone went with the host, above.
      const present = new Set(snap.assets.map((a) => a.key));
      for (const r of oldServices.values()) {
        const [asset, port] = [r.asset as string, r.port as number];
        if (!present.has(asset)) continue;
        change({ kind: "removed", subject: "service", asset, port, what: `Port ${port}/${r.service} closed` });
        db.prepare("UPDATE services SET gone_at = ? WHERE asset = ? AND port = ?").run(at, asset, port);
      }

      // Exposures: new, back, and resolved.
      const open = new Map(
        (db.prepare("SELECT * FROM exposures WHERE resolved_at IS NULL").all() as Row[])
          .filter((r) => scanned.has(r.root as string))
          .map((r) => [r.id as string, r]),
      );
      for (const e of found) {
        const old = db.prepare("SELECT * FROM exposures WHERE id = ?").get(e.id) as Row | undefined;
        if (!old || old.resolved_at)
          change({
            kind: "added",
            subject: "exposure",
            asset: e.asset,
            port: e.port,
            severity: e.severity,
            what: old ? `Back: ${e.title}` : e.title,
            after: e.detail,
          });
        db.prepare(
          `INSERT INTO exposures (id, rule, severity, title, detail, asset, root, port, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (id) DO UPDATE SET severity = excluded.severity, title = excluded.title, detail = excluded.detail, root = excluded.root,
             last_seen = excluded.last_seen, resolved_at = NULL`,
        ).run(e.id, e.rule, e.severity, e.title, e.detail, e.asset, e.root, e.port, at, at);
        open.delete(e.id);
      }
      for (const r of open.values()) {
        change({
          kind: "removed",
          subject: "exposure",
          asset: r.asset as string,
          port: (r.port as number) ?? null,
          severity: r.severity as Severity,
          what: `Resolved: ${r.title}`,
        });
        db.prepare("UPDATE exposures SET resolved_at = ? WHERE id = ?").run(at, r.id as string);
      }

      for (const d of snap.domains) db.prepare("UPDATE domains SET records = ? WHERE name = ?").run(d.records ? JSON.stringify(d.records) : null, d.name);
      for (const o of snap.outside) {
        const root = snap.domains.find((d) => o.via === d.name || o.via.endsWith(`.${d.name}`))?.name ?? o.via;
        db.prepare(
          `INSERT INTO outside (name, seen_as, via, root, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT (name) DO UPDATE SET seen_as = excluded.seen_as, via = excluded.via, root = excluded.root, last_seen = excluded.last_seen`,
        ).run(o.name, o.seenAs, o.via, root, at, at);
      }
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
    return count;
  }

  function upsertService(s: ServiceObs, at: string) {
    db.prepare(
      `INSERT INTO services (asset, port, root, address, service, banner, tls, legacy_tls, http, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (asset, port) DO UPDATE SET root = excluded.root, address = excluded.address, service = excluded.service, banner = excluded.banner,
         tls = excluded.tls, legacy_tls = excluded.legacy_tls, http = excluded.http, last_seen = excluded.last_seen, gone_at = NULL,
         first_seen = CASE WHEN services.gone_at IS NULL THEN services.first_seen ELSE excluded.first_seen END`,
    ).run(
      s.asset,
      s.port,
      s.root,
      s.address,
      s.service,
      s.banner,
      s.tls ? JSON.stringify(s.tls) : null,
      s.legacyTls === null ? null : s.legacyTls ? 1 : 0,
      s.http ? JSON.stringify(s.http) : null,
      at,
      at,
    );
  }

  // ------------------------------------------------------------ What was found

  const toService = (r: Row): Service => ({
    port: r.port as number,
    service: r.service as string,
    address: r.address as string,
    banner: (r.banner as string) ?? null,
    tls: json(r.tls, null),
    legacyTls: r.legacy_tls === null ? null : r.legacy_tls === 1,
    http: json(r.http, null),
    firstSeen: r.first_seen as string,
    lastSeen: r.last_seen as string,
    goneAt: (r.gone_at as string) ?? null,
  });

  const toExposure = (r: Row): ExposureRow => ({
    id: r.id as string,
    rule: r.rule as string,
    severity: r.severity as Severity,
    title: r.title as string,
    detail: r.detail as string,
    asset: r.asset as string,
    root: r.root as string,
    port: (r.port as number) ?? null,
    firstSeen: r.first_seen as string,
    lastSeen: r.last_seen as string,
    resolvedAt: (r.resolved_at as string) ?? null,
  });

  function toAsset(r: Row): Asset {
    const ports = (
      db.prepare("SELECT port FROM services WHERE asset = ? AND gone_at IS NULL ORDER BY port").all(r.key as string) as Array<{ port: number }>
    ).map((p) => p.port);
    const sev = (
      db.prepare("SELECT severity FROM exposures WHERE asset = ? AND resolved_at IS NULL").all(r.key as string) as Array<{ severity: Severity }>
    ).map((s) => s.severity);
    return {
      key: r.key as string,
      kind: r.kind as Asset["kind"],
      root: r.root as string,
      addresses: json(r.addresses, []),
      cname: (r.cname as string) ?? null,
      sources: json(r.sources, []),
      probed: (r.probed as string) ?? null,
      note: (r.note as string) ?? null,
      firstSeen: r.first_seen as string,
      lastSeen: r.last_seen as string,
      goneAt: (r.gone_at as string) ?? null,
      ports,
      exposures: sev.length,
      worst: SEVERITIES.find((s) => sev.includes(s)) ?? null,
    };
  }

  function assets(query: { state?: string | null; q?: string | null } = {}): Asset[] {
    const state = query.state ?? "present";
    if (!["present", "gone", "all"].includes(state)) throw invalid("state is present, gone or all.");
    const where = state === "present" ? "WHERE gone_at IS NULL" : state === "gone" ? "WHERE gone_at IS NOT NULL" : "";
    const q = (query.q ?? "").toLowerCase();
    return (db.prepare(`SELECT * FROM assets ${where} ORDER BY key`).all() as Row[])
      .map(toAsset)
      .filter((a) => !q || `${a.key} ${a.addresses.join(" ")}`.includes(q));
  }

  function asset(key: string) {
    const r = db.prepare("SELECT * FROM assets WHERE key = ?").get(key) as Row | undefined;
    if (!r) throw notFound(`The asset ${key}`);
    return {
      ...toAsset(r),
      services: (db.prepare("SELECT * FROM services WHERE asset = ? ORDER BY gone_at IS NOT NULL, port").all(key) as Row[]).map(toService),
      exposureList: (db.prepare("SELECT * FROM exposures WHERE asset = ? ORDER BY resolved_at IS NOT NULL, last_seen DESC").all(key) as Row[]).map(toExposure),
      changes: (db.prepare("SELECT * FROM changes WHERE asset = ? ORDER BY id DESC LIMIT 50").all(key) as Row[]).map(toChange),
    };
  }

  function exposureList(query: { state?: string | null; severity?: string | null } = {}): ExposureRow[] {
    const state = query.state ?? "open";
    if (!["open", "resolved", "all"].includes(state)) throw invalid("state is open, resolved or all.");
    if (query.severity && !SEVERITIES.includes(query.severity as Severity)) throw invalid(`severity is one of ${SEVERITIES.join(", ")}.`);
    const where = state === "open" ? "resolved_at IS NULL" : state === "resolved" ? "resolved_at IS NOT NULL" : "1";
    return (db.prepare(`SELECT * FROM exposures WHERE ${where} ORDER BY last_seen DESC`).all() as Row[])
      .map(toExposure)
      .filter((e) => !query.severity || e.severity === query.severity)
      .sort((x, y) => SEVERITIES.indexOf(x.severity) - SEVERITIES.indexOf(y.severity) || y.firstSeen.localeCompare(x.firstSeen));
  }

  function certificates(): Certificate[] {
    const byPrint = new Map<string, Certificate>();
    for (const r of db.prepare("SELECT * FROM services WHERE tls IS NOT NULL AND gone_at IS NULL ORDER BY asset, port").all() as Row[]) {
      const t = json<TlsResult>(r.tls, null as unknown as TlsResult);
      const left = Math.floor((Date.parse(t.notAfter) - clock()) / DAY);
      let c = byPrint.get(t.fingerprint);
      if (!c) {
        c = {
          fingerprint: t.fingerprint,
          subject: t.subject,
          issuer: t.issuer,
          sans: t.sans,
          notBefore: t.notBefore,
          notAfter: t.notAfter,
          daysLeft: left,
          state: left < 0 ? "expired" : left <= days.critical ? "critical" : left <= days.warn ? "expiring" : "valid",
          trusted: t.trusted,
          trustError: t.trustError,
          selfSigned: t.selfSigned,
          keyType: t.keyType,
          keyBits: t.keyBits,
          protocols: [],
          legacyTls: false,
          places: [],
        };
        byPrint.set(t.fingerprint, c);
      }
      if (t.protocol && !c.protocols.includes(t.protocol)) c.protocols.push(t.protocol);
      if (r.legacy_tls === 1) c.legacyTls = true;
      c.places.push({ asset: r.asset as string, port: r.port as number, nameMatches: t.nameMatches });
    }
    return [...byPrint.values()].sort((x, y) => x.daysLeft - y.daysLeft);
  }

  const outside = (): Outside[] =>
    (db.prepare("SELECT * FROM outside ORDER BY name").all() as Row[]).map((r) => ({
      name: r.name as string,
      seenAs: r.seen_as as Outside["seenAs"],
      via: r.via as string,
      root: r.root as string,
      firstSeen: r.first_seen as string,
      lastSeen: r.last_seen as string,
    }));

  // ------------------------------------------------------------ Changes

  const toChange = (r: Row): Change => ({
    id: r.id as number,
    scanId: r.scan_id as string,
    at: r.at as string,
    kind: r.kind as Change["kind"],
    subject: r.subject as Change["subject"],
    asset: r.asset as string,
    port: (r.port as number) ?? null,
    severity: (r.severity as Severity) ?? null,
    what: r.what as string,
    before: (r.before as string) ?? null,
    after: (r.after as string) ?? null,
    acknowledgedAt: (r.acknowledged_at as string) ?? null,
    acknowledgedBy: (r.acknowledged_by as string) ?? null,
  });

  function changes(query: { days?: string | null; scan?: string | null } = {}): Change[] {
    const d = query.days == null ? 30 : Number(query.days);
    if (!Number.isInteger(d) || d < 1 || d > 400) throw invalid("days is a whole number, 1 to 400.");
    const from = new Date(clock() - d * DAY).toISOString();
    const rows = query.scan
      ? db.prepare("SELECT * FROM changes WHERE scan_id = ? ORDER BY id DESC LIMIT 2000").all(query.scan)
      : db.prepare("SELECT * FROM changes WHERE at >= ? ORDER BY id DESC LIMIT 2000").all(from);
    return (rows as Row[]).map(toChange);
  }

  function acknowledge(id: string, actor: string): Change {
    const r = db.prepare("SELECT * FROM changes WHERE id = ?").get(Number(id)) as Row | undefined;
    if (!r || !/^\d+$/.test(id)) throw notFound("The change");
    if (!r.acknowledged_at) db.prepare("UPDATE changes SET acknowledged_at = ?, acknowledged_by = ? WHERE id = ?").run(now(), actor, r.id as number);
    return toChange(db.prepare("SELECT * FROM changes WHERE id = ?").get(r.id as number) as Row);
  }

  const auditLog = (): AuditEntry[] =>
    db.prepare("SELECT id, at, actor, action, target, detail FROM audit ORDER BY id DESC LIMIT 500").all() as unknown as AuditEntry[];

  // ------------------------------------------------------------ Summary

  function summary() {
    const count = (sql: string) => (db.prepare(sql).get() as { n: number }).n;
    const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
    for (const r of db.prepare("SELECT severity, COUNT(*) AS n FROM exposures WHERE resolved_at IS NULL GROUP BY severity").all() as Array<{
      severity: Severity;
      n: number;
    }>)
      bySeverity[r.severity] = r.n;
    const certs = certificates();
    const last = lastScan();
    const ds = domains();
    const ports = db
      .prepare("SELECT port, service, COUNT(*) AS n FROM services WHERE gone_at IS NULL GROUP BY port, service ORDER BY n DESC, port")
      .all() as Array<{
      port: number;
      service: string;
      n: number;
    }>;
    return {
      assets: count("SELECT COUNT(*) AS n FROM assets WHERE gone_at IS NULL"),
      newAssets: count(`SELECT COUNT(*) AS n FROM assets WHERE gone_at IS NULL AND first_seen >= '${new Date(clock() - 7 * DAY).toISOString()}'`),
      services: count("SELECT COUNT(*) AS n FROM services WHERE gone_at IS NULL"),
      exposures: { ...bySeverity, total: SEVERITIES.reduce((n, s) => n + bySeverity[s], 0) },
      certificates: {
        total: certs.length,
        expiring: certs.filter((c) => c.state === "critical" || c.state === "expiring").length,
        expired: certs.filter((c) => c.state === "expired").length,
      },
      unacknowledged: count("SELECT COUNT(*) AS n FROM changes WHERE acknowledged_at IS NULL"),
      outside: count("SELECT COUNT(*) AS n FROM outside"),
      domains: {
        verified: ds.filter((d) => d.state === "verified").length,
        pending: ds.filter((d) => d.state === "pending").length,
        lost: ds.filter((d) => d.state === "lost").length,
      },
      ranges: count("SELECT COUNT(*) AS n FROM ranges"),
      ports: ports.map((p) => ({ port: p.port, service: p.service, count: p.n })),
      lastScan: last,
      scanning: running !== null,
      nextScanAt: new Date(last ? Date.parse(last.startedAt) + scanHours * 3_600_000 : clock()).toISOString(),
      // How scans run, from the environment: shown, not changed, on the Scans page.
      settings: {
        scanHours,
        ratePerSecond: options.ratePerSecond ?? null,
        ports: options.ports,
        certificateTransparency: options.ct !== null,
        allowPrivate,
        certWarnDays: days.warn,
      },
    };
  }

  /**
   * Whether the schedule calls for a scan now: when there is something to scan, and the last scan is older than the
   * interval or did not cover the same roots, so a domain just verified or a range just added is scanned soon.
   */
  function due(): boolean {
    if (running) return false;
    const verified = (db.prepare("SELECT name FROM domains WHERE state = 'verified'").all() as Array<{ name: string }>).map((r) => r.name);
    const roots = [...verified, ...ranges().map((r) => r.cidr)].sort();
    if (!roots.length) return false;
    const last = lastScan();
    if (!last || clock() - Date.parse(last.startedAt) >= scanHours * 3_600_000) return true;
    return JSON.stringify([...last.roots].sort()) !== JSON.stringify(roots);
  }

  /** Scans that were running when the process stopped did not finish. */
  function recover() {
    db.prepare("UPDATE scans SET state = 'failed', finished_at = ?, error = 'Attack Surface stopped during the scan.' WHERE state = 'running'").run(now());
  }

  /** Scans and their changes older than 400 days go; the audit log stays. */
  function purge() {
    db.prepare("DELETE FROM scans WHERE started_at < ?").run(new Date(clock() - 400 * DAY).toISOString());
  }

  return {
    domains,
    domain: (id: string) => toDomain(domainRow(id)),
    createDomain,
    verifyDomain,
    deleteDomain,
    ranges,
    createRange,
    deleteRange,
    scans,
    scan: scanById,
    startScan,
    due,
    recover,
    purge,
    assets,
    asset,
    exposures: exposureList,
    certificates,
    outside,
    changes,
    acknowledge,
    audit: auditLog,
    summary,
    /** Resolves when the running scan, if any, has finished. */
    idle: () => running ?? Promise.resolve(),
  };
}

export type Surface = ReturnType<typeof createSurface>;
