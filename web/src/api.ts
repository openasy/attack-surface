// The UI is an ordinary client of the public API (ADR 0014, 0018). Types follow openapi.json.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Another OpenAsy product of this install, from OPENASY_PRODUCTS. */
export interface ProductLink {
  id: string;
  url: string;
}

export interface DomainRecords {
  a: string[];
  aaaa: string[];
  mx: string[];
  ns: string[];
  spf: string | null;
  dmarc: string | null;
  caa: string[];
}

export interface Domain {
  id: string;
  name: string;
  state: "pending" | "verified" | "lost";
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

export interface Tls {
  fingerprint: string;
  subject: string | null;
  issuer: string | null;
  sans: string[];
  notBefore: string;
  notAfter: string;
  keyType: string | null;
  keyBits: number | null;
  protocol: string | null;
  trusted: boolean;
  trustError: string | null;
  nameMatches: boolean;
  selfSigned: boolean;
}

export interface Service {
  port: number;
  service: string;
  address: string;
  banner: string | null;
  tls: Tls | null;
  legacyTls: boolean | null;
  http: { status: number; headers: Record<string, string>; title: string | null; login: boolean } | null;
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
  sources: Array<"dns" | "certificate" | "mx" | "ns" | "range">;
  probed: string | null;
  note: string | null;
  firstSeen: string;
  lastSeen: string;
  goneAt: string | null;
  ports: number[];
  exposures: number;
  worst: Severity | null;
}

export interface Exposure {
  id: string;
  rule: string;
  severity: Severity;
  title: string;
  detail: string;
  asset: string;
  root: string;
  port: number | null;
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

export interface AssetDetail extends Asset {
  services: Service[];
  exposureList: Exposure[];
  changes: Change[];
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

export interface Summary {
  assets: number;
  newAssets: number;
  services: number;
  exposures: Record<Severity, number> & { total: number };
  certificates: { total: number; expiring: number; expired: number };
  unacknowledged: number;
  outside: number;
  domains: { verified: number; pending: number; lost: number };
  ranges: number;
  ports: Array<{ port: number; service: string; count: number }>;
  lastScan: Scan | null;
  scanning: boolean;
  nextScanAt: string;
  settings: { scanHours: number; ratePerSecond: number | null; ports: number[]; certificateTransparency: boolean; allowPrivate: boolean; certWarnDays: number };
}

export class Unauthorized extends Error {}
/** The signed-in owner or admin has no second factor yet; the sign-in gate asks for one. */
export class MfaSetupRequired extends Error {}
export class ApiError extends Error {}

// The session is an HttpOnly cookie set by sign-in (@openasy/auth); the browser sends it, nothing is stored here.
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers },
  });
  if (!res.ok) {
    const problem = (await res.json().catch(() => ({}))) as { code?: string; detail?: string };
    if (res.status === 401) throw new Unauthorized(problem.detail);
    if (problem.code === "mfa-setup-required") throw new MfaSetupRequired(problem.detail);
    throw new ApiError(problem.detail ?? `${path}: ${res.status}`);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}
