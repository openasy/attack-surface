// DNS, read the way any resolver on the internet reads it: the records of the verified domains, the proof of
// ownership, and the addresses of the names found. Nothing is sent to the domains' own servers but ordinary queries,
// and no name is guessed (ADR 0067).
import { Resolver } from "node:dns/promises";

/** What is asked of DNS. Each lookup returns an empty list for a name without that record; tests replace it whole. */
export interface Dns {
  txt(name: string): Promise<string[]>;
  a(name: string): Promise<string[]>;
  aaaa(name: string): Promise<string[]>;
  /** The target of a CNAME at the name itself, or null. */
  cname(name: string): Promise<string | null>;
  mx(name: string): Promise<string[]>;
  ns(name: string): Promise<string[]>;
  caa(name: string): Promise<string[]>;
}

/** Answers that mean "nothing there"; any other failure, such as a timeout, is thrown so a scan does not read it as gone. */
const EMPTY = new Set(["ENODATA", "ENOTFOUND", "ENONAME", "NXDOMAIN", "ENOTIMP"]);

async function orEmpty<T>(lookup: Promise<T[]>): Promise<T[]> {
  try {
    return await lookup;
  } catch (err) {
    if (EMPTY.has((err as { code?: string }).code ?? "")) return [];
    throw err;
  }
}

/** The system's resolver, or the servers in ATTACK_SURFACE_DNS_SERVERS. */
export function systemDns(servers: string[] = []): Dns {
  const r = new Resolver({ timeout: 5000, tries: 2 });
  if (servers.length) r.setServers(servers);
  const clean = (n: string) => n.toLowerCase().replace(/\.$/, "");
  return {
    txt: async (name) => (await orEmpty(r.resolveTxt(name))).map((parts) => parts.join("")),
    a: (name) => orEmpty(r.resolve4(name)),
    aaaa: (name) => orEmpty(r.resolve6(name)),
    cname: async (name) => (await orEmpty(r.resolveCname(name))).map(clean)[0] ?? null,
    mx: async (name) => (await orEmpty(r.resolveMx(name))).sort((x, y) => x.priority - y.priority).map((m) => clean(m.exchange)),
    ns: async (name) => (await orEmpty(r.resolveNs(name))).map(clean),
    caa: async (name) =>
      (await orEmpty(r.resolveCaa(name))).flatMap((c) =>
        Object.entries(c)
          .filter(([k]) => k !== "critical")
          .map(([k, v]) => `${k} ${String(v)}`),
      ),
  };
}

/** Where the proof of ownership of a domain is published, as _acme-challenge is for Let's Encrypt. */
export const proofName = (domain: string) => `_openasy-attack-surface.${domain}`;
export const proofValue = (token: string) => `openasy-attack-surface-verification=${token}`;

/** Whether the domain's proof record holds this token. */
export async function hasProof(dns: Dns, domain: string, token: string): Promise<boolean> {
  return (await dns.txt(proofName(domain))).some((t) => t.trim() === proofValue(token));
}

export interface DomainRecords {
  a: string[];
  aaaa: string[];
  mx: string[];
  ns: string[];
  /** The SPF policy, the TXT record that starts with v=spf1, or null. */
  spf: string | null;
  /** The DMARC policy at _dmarc, or null. */
  dmarc: string | null;
  caa: string[];
}

export async function domainRecords(dns: Dns, domain: string): Promise<DomainRecords> {
  const [a, aaaa, mx, ns, txt, dmarc, caa] = await Promise.all([
    dns.a(domain),
    dns.aaaa(domain),
    dns.mx(domain),
    dns.ns(domain),
    dns.txt(domain),
    dns.txt(`_dmarc.${domain}`),
    dns.caa(domain),
  ]);
  return {
    a,
    aaaa,
    mx,
    ns,
    spf: txt.find((t) => /^v=spf1(\s|$)/i.test(t)) ?? null,
    dmarc: dmarc.find((t) => /^v=DMARC1(;|\s|$)/i.test(t)) ?? null,
    caa,
  };
}
