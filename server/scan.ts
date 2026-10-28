// One scan: from the verified roots to what answers (ADR 0067). Discovery is passive, DNS and certificate
// transparency only, so no name is guessed and nothing of a domain's is touched to find its names. Then each name and
// each address of a range is probed on a short list of ports, through the limiter, and only after assertProbe() says
// it is in scope. What it finds is a snapshot; surface.ts compares it with the last one.
import type { CtSource } from "./ct.ts";
import { domainRecords, type DomainRecords, type Dns } from "./dns.ts";
import type { HttpResult, Limiter, PortResult, Prober, Target, TlsResult } from "./probe.ts";
import { addressRefusal, addresses, assertProbe, rootOf, type Cidr, type Roots } from "./scope.ts";

/** Common ports and what usually answers there. A connect only: no SYN scan, no service fingerprinting. */
export const SERVICES: Record<number, string> = {
  21: "ftp",
  22: "ssh",
  23: "telnet",
  25: "smtp",
  53: "dns",
  80: "http",
  110: "pop3",
  143: "imap",
  443: "https",
  445: "smb",
  465: "smtps",
  587: "submission",
  993: "imaps",
  995: "pop3s",
  1433: "mssql",
  1521: "oracle",
  2375: "docker",
  3000: "http",
  3306: "mysql",
  3389: "rdp",
  5432: "postgresql",
  5601: "http",
  5900: "vnc",
  6379: "redis",
  8000: "http",
  8080: "http",
  8443: "https",
  9200: "elasticsearch",
  11211: "memcached",
  27017: "mongodb",
};
export const DEFAULT_PORTS = Object.keys(SERVICES).map(Number);

/** Ports read with one GET /, over TLS for the second set; TLS only for the third. Others give their banner only. */
const HTTP = new Set([80, 2375, 3000, 5601, 8000, 8080, 9200]);
const HTTPS = new Set([443, 8443]);
const TLS = new Set([465, 636, 993, 995]);

export const serviceOf = (port: number) => SERVICES[port] ?? "unknown";

export interface AssetObs {
  /** The host name, or the address for one found in a range. */
  key: string;
  kind: "name" | "address";
  /** The verified domain or the range it is under. */
  root: string;
  addresses: string[];
  cname: string | null;
  /** Where it was found: dns, certificate, mx, ns or range. */
  sources: string[];
  /** The address its ports were probed at, or null with why not. */
  probed: string | null;
  note: string | null;
  /** A CNAME whose target does not resolve. */
  dangling: boolean;
}

export interface ServiceObs {
  asset: string;
  root: string;
  address: string;
  port: number;
  service: string;
  banner: string | null;
  tls: TlsResult | null;
  /** Whether TLS 1.0 or 1.1 is still taken; null when there is no TLS. */
  legacyTls: boolean | null;
  http: HttpResult | null;
}

export interface OutsideObs {
  name: string;
  /** How it was seen: on a certificate, as a CNAME target, a mail or a name server. */
  seenAs: "certificate" | "cname" | "mx" | "ns";
  via: string;
}

export interface DomainObs {
  name: string;
  records: DomainRecords | null;
}

export interface Snapshot {
  domains: DomainObs[];
  assets: AssetObs[];
  services: ServiceObs[];
  outside: OutsideObs[];
  /** What went wrong along the way, such as certificate transparency not answering; the scan still finishes. */
  warnings: string[];
  /** How many connections were made, for the scan's record. */
  probes: number;
}

export interface ScanDeps {
  dns: Dns;
  /** null when certificate transparency is turned off (ATTACK_SURFACE_CT_URL=off). */
  ct: CtSource | null;
  prober: Prober;
  limit: Limiter;
  ports: number[];
  /** The most names one scan resolves and probes. */
  maxNames?: number;
}

export interface ScanRoots extends Roots {
  ranges: readonly Cidr[];
}

/** Runs fn over items, at most n at once. For DNS, which goes to resolvers and not to the targets. */
async function pool<T>(items: T[], n: number, fn: (item: T) => Promise<void>) {
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (i < items.length) await fn(items[i++]!);
    }),
  );
}

export async function runScan(roots: ScanRoots, deps: ScanDeps): Promise<Snapshot> {
  const { dns, ct, prober, limit, ports, maxNames = 2000 } = deps;
  const warnings: string[] = [];
  const outside = new Map<string, OutsideObs>();
  const seeOutside = (name: string, seenAs: OutsideObs["seenAs"], via: string) => {
    if (!outside.has(name)) outside.set(name, { name, seenAs, via });
  };
  /** Names to resolve, each with where it was seen. Only names under a verified domain get here. */
  const names = new Map<string, Set<string>>();
  const found = (name: string, source: string, via: string, seenAs: OutsideObs["seenAs"]) => {
    if (!rootOf(name, roots.domains)) return seeOutside(name, seenAs, via);
    if (!names.has(name)) names.set(name, new Set());
    names.get(name)!.add(source);
  };

  const domains: DomainObs[] = [];
  for (const domain of roots.domains) {
    let records: DomainRecords | null = null;
    try {
      records = await domainRecords(dns, domain);
    } catch (err) {
      warnings.push(`DNS of ${domain}: ${(err as Error).message}`);
    }
    domains.push({ name: domain, records });
    found(domain, "dns", domain, "certificate");
    for (const mx of records?.mx ?? []) found(mx, "mx", domain, "mx");
    for (const ns of records?.ns ?? []) found(ns, "ns", domain, "ns");
    if (!ct) continue;
    try {
      for (const n of await ct(domain)) found(n.name, "certificate", domain, "certificate");
    } catch (err) {
      warnings.push(`Certificate transparency for ${domain}: ${(err as Error).message}`);
    }
  }

  let list = [...names.keys()].sort((a, b) => a.length - b.length || a.localeCompare(b));
  if (list.length > maxNames) {
    warnings.push(`${list.length} names were found; the first ${maxNames} were scanned.`);
    list = list.slice(0, maxNames);
  }

  const assets: AssetObs[] = [];
  await pool(list, 10, async (name) => {
    try {
      const [a, aaaa, cname] = await Promise.all([dns.a(name), dns.aaaa(name), dns.cname(name)]);
      const all = [...a, ...aaaa];
      if (cname && !rootOf(cname, roots.domains)) seeOutside(cname, "cname", name);
      // A name that resolves to nothing is history in the logs, not an asset, unless a CNAME still points away.
      if (!all.length && !cname) return;
      const probed = all.find((x) => addressRefusal(x, roots) === null) ?? null;
      assets.push({
        key: name,
        kind: "name",
        root: rootOf(name, roots.domains)!,
        addresses: all,
        cname,
        sources: [...names.get(name)!].sort(),
        probed,
        note: probed || !all.length ? null : `${all[0]} is ${addressRefusal(all[0]!, roots)}.`,
        dangling: !all.length,
      });
    } catch (err) {
      warnings.push(`DNS of ${name}: ${(err as Error).message}`);
    }
  });
  for (const range of roots.ranges) {
    for (const address of addresses(range)) {
      const refusal = addressRefusal(address, roots);
      assets.push({
        key: address,
        kind: "address",
        root: range.cidr,
        addresses: [address],
        cname: null,
        sources: ["range"],
        probed: refusal ? null : address,
        note: refusal ? `${address} is ${refusal}.` : null,
        dangling: false,
      });
    }
  }

  // Each address and port is connected to once a scan, however many names point there.
  const opened = new Map<string, Promise<PortResult>>();
  let probes = 0;
  const probe = <T>(t: Target, fn: () => Promise<T>) =>
    limit(() => {
      assertProbe(t, roots);
      probes++;
      return fn();
    });
  const services: ServiceObs[] = [];
  await Promise.all(
    assets.flatMap((asset) =>
      asset.probed === null
        ? []
        : ports.map(async (port) => {
            const t: Target = { name: asset.kind === "name" ? asset.key : null, address: asset.probed!, port };
            const k = `${t.address}|${port}`;
            if (!opened.has(k))
              opened.set(
                k,
                probe(t, () => prober.port(t)),
              );
            const result = await opened.get(k)!;
            if (!result.open) return;
            let tls: TlsResult | null = null;
            let legacyTls: boolean | null = null;
            if (HTTPS.has(port) || TLS.has(port)) {
              tls = await probe(t, () => prober.tls(t));
              if (tls) legacyTls = await probe(t, () => prober.legacyTls(t));
            }
            const http = HTTP.has(port) || (HTTPS.has(port) && tls) ? await probe(t, () => prober.http(t, HTTPS.has(port))) : null;
            services.push({
              asset: asset.key,
              root: asset.root,
              address: t.address,
              port,
              service: serviceOf(port),
              banner: result.banner,
              tls,
              legacyTls,
              http,
            });
          }),
    ),
  );

  // An address of a range is an asset only when something answers there.
  const answering = new Set(services.map((s) => s.asset));
  services.sort((x, y) => x.asset.localeCompare(y.asset) || x.port - y.port);
  return {
    domains,
    assets: assets.filter((a) => a.kind === "name" || answering.has(a.key)).sort((x, y) => x.key.localeCompare(y.key)),
    services,
    outside: [...outside.values()].sort((x, y) => x.name.localeCompare(y.name)),
    warnings,
    probes,
  };
}
