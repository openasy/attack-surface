// Exposures: what a snapshot shows that should not be open, or is open and set up badly (ADR 0067). Each comes from
// what was observed: a port that answered, a certificate, a header, a DNS record. None is a guess from a version
// number, and none was found by sending anything to find it.
import { createHash } from "node:crypto";
import type { Snapshot, ServiceObs } from "./scan.ts";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Exposure {
  /** The same exposure across scans: its rule, asset and port. */
  id: string;
  rule: string;
  severity: Severity;
  title: string;
  detail: string;
  asset: string;
  root: string;
  port: number | null;
}

/** When certificates warn (OPENASY_CERT_WARN_DAYS, ADR 0052): the largest value warns, 7 days or less is urgent. */
export interface CertDays {
  warn: number;
  critical: number;
  /** Every threshold, largest first, and 0: a certificate is reported again each time it crosses one. */
  steps: number[];
}

export function certDays(value: string | undefined): CertDays {
  const days = (value ?? "30,14,7,1")
    .split(",")
    .map((d) => Number(d.trim()))
    .filter((d) => Number.isInteger(d) && d > 0);
  const warn = days.length ? Math.max(...days) : 30;
  return { warn, critical: Math.min(7, warn), steps: [...new Set([...days, 0])].sort((a, b) => b - a) };
}

const DATABASES = new Set([1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017]);
const REMOTE: Record<number, string> = { 23: "Telnet", 3389: "Remote Desktop (RDP)", 5900: "VNC" };
const NAMES: Record<number, string> = {
  1433: "SQL Server",
  1521: "Oracle",
  3306: "MySQL",
  5432: "PostgreSQL",
  6379: "Redis",
  9200: "Elasticsearch",
  11211: "Memcached",
  27017: "MongoDB",
};

const DAY = 86_400_000;
const isHtml = (s: ServiceObs) => (s.http?.headers["content-type"] ?? "").includes("text/html");

export function exposures(snap: Snapshot, now: number, days: CertDays = certDays(undefined)): Exposure[] {
  const out: Exposure[] = [];
  const add = (e: Omit<Exposure, "id">) =>
    out.push({
      ...e,
      id: createHash("sha256")
        .update(`${e.rule}|${e.asset}|${e.port ?? ""}`)
        .digest("hex")
        .slice(0, 20),
    });

  for (const d of snap.domains) {
    if (!d.records) continue;
    const base = { asset: d.name, root: d.name, port: null };
    if (d.records.mx.length && !d.records.spf)
      add({
        ...base,
        rule: "spf-missing",
        severity: "low",
        title: "No SPF record",
        detail: "Mail is received for the domain, and nothing says which servers may send as it.",
      });
    if (!d.records.dmarc)
      add({
        ...base,
        rule: "dmarc-missing",
        severity: "low",
        title: "No DMARC policy",
        detail: `_dmarc.${d.name} has no v=DMARC1 record, so mail forged as the domain is not refused.`,
      });
    else if (/;\s*p\s*=\s*none/i.test(d.records.dmarc))
      add({ ...base, rule: "dmarc-none", severity: "info", title: "DMARC policy is none", detail: "Forged mail is reported, not refused." });
    if (!d.records.caa.length)
      add({
        ...base,
        rule: "caa-missing",
        severity: "info",
        title: "No CAA record",
        detail: "Any certificate authority may issue certificates for the domain.",
      });
  }

  for (const a of snap.assets) {
    if (a.dangling)
      add({
        asset: a.key,
        root: a.root,
        port: null,
        rule: "dangling-cname",
        severity: "high",
        title: "CNAME to a name that does not resolve",
        detail: `${a.key} points to ${a.cname}, which has no address. Whoever registers or claims it can serve pages as ${a.key}.`,
      });
    else if (a.kind === "name" && a.probed === null && a.note)
      add({ asset: a.key, root: a.root, port: null, rule: "private-address", severity: "low", title: "Public name on a private address", detail: a.note });
  }

  for (const s of snap.services) {
    const base = { asset: s.asset, root: s.root, port: s.port };
    if (DATABASES.has(s.port))
      add({
        ...base,
        rule: "database-exposed",
        severity: "high",
        title: `${NAMES[s.port]} open to the internet`,
        detail: `Port ${s.port} accepts connections from anywhere. Databases belong on a private network or behind an allow list.`,
      });
    if (REMOTE[s.port])
      add({
        ...base,
        rule: "remote-access-exposed",
        severity: "high",
        title: `${REMOTE[s.port]} open to the internet`,
        detail: `Port ${s.port} answers; remote access belongs behind a VPN.`,
      });
    if (s.port === 445)
      add({ ...base, rule: "smb-exposed", severity: "high", title: "SMB open to the internet", detail: "File sharing on port 445 answers from anywhere." });
    if (s.port === 2375)
      add({
        ...base,
        rule: "docker-api-exposed",
        severity: "critical",
        title: "Docker API without TLS",
        detail: "Port 2375 is Docker's API in plain text. Whoever reaches it runs containers as root on the host.",
      });
    if (s.port === 21)
      add({ ...base, rule: "ftp-exposed", severity: "medium", title: "FTP open to the internet", detail: "FTP sends passwords in plain text." });
    if (s.port === 22) add({ ...base, rule: "ssh-exposed", severity: "low", title: "SSH open to the internet", detail: s.banner ?? "Port 22 answers." });

    if (s.tls) {
      const left = (Date.parse(s.tls.notAfter) - now) / DAY;
      const cert = `${s.tls.subject ?? "The certificate"}, issued by ${s.tls.issuer ?? "an unknown issuer"}`;
      if (left <= 0)
        add({
          ...base,
          rule: "tls-expired",
          severity: "critical",
          title: "Certificate expired",
          detail: `${cert}, expired on ${s.tls.notAfter.slice(0, 10)}.`,
        });
      else if (left <= days.warn)
        add({
          ...base,
          rule: "tls-expiring",
          severity: left <= days.critical ? "high" : "medium",
          title: `Certificate expires in ${Math.ceil(left)} day${Math.ceil(left) === 1 ? "" : "s"}`,
          detail: `${cert}, valid until ${s.tls.notAfter.slice(0, 10)}.`,
        });
      if (!s.tls.nameMatches)
        add({
          ...base,
          rule: "tls-name-mismatch",
          severity: "medium",
          title: "Certificate is for another name",
          detail: `${cert}, for ${s.tls.sans.join(", ") || s.tls.subject}, not ${s.asset}.`,
        });
      if (!s.tls.trusted)
        add({
          ...base,
          rule: "tls-untrusted",
          severity: "medium",
          title: s.tls.selfSigned ? "Self-signed certificate" : "Certificate not trusted",
          detail: `${cert}: ${s.tls.trustError}.`,
        });
      if (s.tls.keyType === "rsa" && (s.tls.keyBits ?? 0) < 2048)
        add({ ...base, rule: "tls-weak-key", severity: "medium", title: "Weak certificate key", detail: `RSA ${s.tls.keyBits} bits; 2048 is the least.` });
      if (s.legacyTls)
        add({
          ...base,
          rule: "tls-legacy",
          severity: "medium",
          title: "TLS 1.0 or 1.1 accepted",
          detail: "Both are retired (RFC 8996); browsers refuse them.",
        });
    }

    const http = s.http;
    if (!http) continue;
    const location = http.headers.location ?? "";
    if (!s.tls && s.port === 80 && http.status < 300 && s.asset !== s.address)
      add({
        ...base,
        rule: "http-only",
        severity: "medium",
        title: "Served over plain HTTP",
        detail: `http://${s.asset}/ answers ${http.status} instead of sending people to https://.`,
      });
    if (s.port === 80 && http.status >= 300 && http.status < 400 && !location.startsWith("https://"))
      add({
        ...base,
        rule: "http-only",
        severity: "medium",
        title: "Redirect stays on plain HTTP",
        detail: `http://${s.asset}/ redirects to ${location || "nowhere"}.`,
      });
    if (http.login)
      add({
        ...base,
        rule: "login-page",
        severity: "medium",
        title: "Login page open to the internet",
        detail: `${http.title ?? "A page with a password field"}: a sign-in that anyone can try. Put it behind single sign-on or a VPN if it is not for the public.`,
      });
    const banner = [http.headers.server, http.headers["x-powered-by"]].filter((v) => v && /\d/.test(v));
    if (banner.length) add({ ...base, rule: "version-disclosed", severity: "info", title: "Software version in headers", detail: banner.join(", ") });
    if (http.status < 300 && isHtml(s)) {
      const csp = http.headers["content-security-policy"] ?? "";
      const missing = [
        ...(s.tls && !http.headers["strict-transport-security"] ? ["Strict-Transport-Security"] : []),
        ...(!csp ? ["Content-Security-Policy"] : []),
        ...(!/nosniff/i.test(http.headers["x-content-type-options"] ?? "") ? ["X-Content-Type-Options"] : []),
        ...(!http.headers["x-frame-options"] && !/frame-ancestors/i.test(csp) ? ["X-Frame-Options or frame-ancestors"] : []),
      ];
      if (missing.length) add({ ...base, rule: "headers-missing", severity: "low", title: "Security headers missing", detail: missing.join(", ") });
    }
  }
  return out;
}
