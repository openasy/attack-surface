// Starts the app on a random port for tests, with fake DNS, certificate transparency and network: nothing a test
// does leaves this machine.
import { createHmac } from "node:crypto";
import { createServer, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createAuth } from "@openasy/auth";
import { createApp, type AppOptions } from "./app.ts";
import type { CtName } from "./ct.ts";
import { openDb } from "./db.ts";
import type { Dns } from "./dns.ts";
import { createLimiter, type HttpResult, type Prober, type Target, type TlsResult } from "./probe.ts";
import { createSurface, type SurfaceOptions } from "./surface.ts";

export const ADMIN_TOKEN = "test-admin-token";
export const T0 = Date.parse("2026-10-28T06:00:00Z");
const DAY = 86_400_000;

export interface Zone {
  [name: string]: { a?: string[]; aaaa?: string[]; cname?: string; txt?: string[]; mx?: string[]; ns?: string[]; caa?: string[] };
}

/** DNS from a table the test changes as it goes. `asked` lists every name looked up. */
export function fakeDns(zone: Zone): Dns & { zone: Zone; asked: string[] } {
  const asked: string[] = [];
  const get = (name: string) => (asked.push(name), zone[name] ?? {});
  return {
    zone,
    asked,
    txt: async (n) => get(n).txt ?? [],
    a: async (n) => get(n).a ?? [],
    aaaa: async (n) => get(n).aaaa ?? [],
    cname: async (n) => get(n).cname ?? null,
    mx: async (n) => get(n).mx ?? [],
    ns: async (n) => get(n).ns ?? [],
    caa: async (n) => get(n).caa ?? [],
  };
}

export const tls = (over: Partial<TlsResult> = {}): TlsResult => ({
  fingerprint: "a".repeat(64),
  subject: "www.example.com",
  issuer: "R11",
  sans: ["www.example.com"],
  notBefore: new Date(T0 - 30 * DAY).toISOString(),
  notAfter: new Date(T0 + 60 * DAY).toISOString(),
  keyType: "ec",
  keyBits: null,
  protocol: "TLSv1.3",
  trusted: true,
  trustError: null,
  nameMatches: true,
  selfSigned: false,
  ...over,
});

export const http = (over: Partial<HttpResult> = {}): HttpResult => ({
  status: 200,
  headers: {
    "content-type": "text/html",
    "strict-transport-security": "max-age=63072000",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
  },
  title: "Example",
  login: false,
  ...over,
});

export interface Answer {
  banner?: string;
  tls?: TlsResult;
  legacyTls?: boolean;
  http?: HttpResult;
}

/** A network of `address:port` that answer; every probe is recorded, so a test can say what was never touched. */
export function fakeProber(open: Record<string, Answer>): Prober & { open: Record<string, Answer>; calls: Array<Target & { kind: string }> } {
  const calls: Array<Target & { kind: string }> = [];
  const find = (kind: string, t: Target) => (calls.push({ kind, ...t }), open[`${t.address}:${t.port}`]);
  return {
    open,
    calls,
    port: async (t) => {
      const a = find("port", t);
      return { open: Boolean(a), banner: a?.banner ?? null };
    },
    tls: async (t) => find("tls", t)?.tls ?? null,
    legacyTls: async (t) => find("legacyTls", t)?.legacyTls ?? false,
    http: async (t) => find("http", t)?.http ?? null,
  };
}

/** A domain's proof, as the owner publishes it. */
export const proof = (value: string) => ({ txt: [value] });

export function testZone(): Zone {
  return {
    "example.com": { a: ["198.51.100.10"], mx: ["mail.example.com", "aspmx.l.google.com"], ns: ["ns1.dnsprovider.net"], txt: ["v=spf1 mx -all"] },
    "_dmarc.example.com": { txt: ["v=DMARC1; p=reject"] },
    "www.example.com": { a: ["198.51.100.10"] },
    "mail.example.com": { a: ["198.51.100.12"] },
    "staging-admin.example.com": { a: ["203.0.113.57"] },
    "docs-old.example.com": { cname: "acme-docs.s3-website.example-cloud.net" },
    "intranet.example.com": { a: ["10.0.4.2"] },
  };
}

export const testCt = (): Record<string, CtName[]> => ({
  "example.com": [
    "example.com",
    "www.example.com",
    "staging-admin.example.com",
    "docs-old.example.com",
    "intranet.example.com",
    "old.example.com",
    "partner-portal.com",
  ].map((name) => ({ name, notAfter: null })),
});

export function testNetwork(): Record<string, Answer> {
  return {
    "198.51.100.10:443": { tls: tls(), http: http() },
    "198.51.100.10:80": { http: http({ status: 301, headers: { location: "https://www.example.com/" } }) },
    "198.51.100.12:25": { banner: "220 mail.example.com ESMTP Postfix" },
    "203.0.113.57:9200": { http: http({ headers: { "content-type": "application/json" } }) },
    "203.0.113.57:22": { banner: "SSH-2.0-OpenSSH_8.9p1" },
  };
}

export function testSurface(over: Partial<SurfaceOptions> = {}) {
  const db = openDb(":memory:");
  let now = T0;
  const dns = fakeDns(testZone());
  const ctNames = testCt();
  const ctAsked: string[] = [];
  const prober = fakeProber(testNetwork());
  const surface = createSurface(db, {
    dns,
    ct: async (d) => (ctAsked.push(d), ctNames[d] ?? []),
    prober,
    limit: createLimiter(1000, 50),
    ports: [22, 25, 80, 443, 3389, 9200],
    clock: () => now,
    ...over,
  });
  /** Adds and verifies a domain the way its owner would. */
  async function own(name: string) {
    const d = surface.createDomain({ name }, "Olivia");
    dns.zone[d.proof.name] = proof(d.proof.value);
    return surface.verifyDomain(d.id, "Olivia");
  }
  async function scan() {
    const { scan, done } = surface.startScan("manual", "Olivia");
    await done;
    return surface.scan(scan.id);
  }
  return { db, dns, ctNames, ctAsked, prober, surface, own, scan, later: (ms: number) => (now += ms), now: () => now };
}

export async function startApp(opts: Partial<AppOptions> & { version: string; surfaceOptions?: Partial<SurfaceOptions> }) {
  const { surfaceOptions, ...appOptions } = opts;
  const t = testSurface(surfaceOptions);
  const { db, surface } = t;
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "attack-surface", productName: "OpenAsy Attack Surface", origin: base });
  handler = createApp({ db, surface, auth, adminToken: ADMIN_TOKEN, ...appOptions });
  const as =
    (token: string) =>
    (path: string, init: RequestInit = {}) =>
      fetch(base + path, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers } });
  const admin = as(ADMIN_TOKEN);
  const get = async (path: string) => (await (await admin(path)).json()) as any;
  const send = (method: string, path: string, body?: unknown) => admin(path, { method, ...(body !== undefined && { body: JSON.stringify(body) }) });
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));

  /** The owner, signed in with a second factor, makes an API token for each role. */
  async function roles() {
    const jar = new Map<string, string>();
    const browser = async (path: string, body: unknown) => {
      const res = await fetch(base + path, {
        method: "POST",
        headers: { origin: base, cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; "), "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      for (const c of res.headers.getSetCookie()) {
        const [pair] = c.split(";");
        const i = pair!.indexOf("=");
        jar.set(pair!.slice(0, i), pair!.slice(i + 1));
      }
      return res;
    };
    const setup = new URL(auth.setupLink()!).searchParams.get("setup");
    await browser("/api/v1/auth/setup", { token: setup, name: "Olivia", email: "owner@example.com", password: "correct horse battery staple 42" });
    const { secret } = (await (await browser("/api/v1/auth/me/totp", {})).json()) as { secret: string };
    await browser("/api/v1/auth/me/totp/confirm", { code: totp(secret) });
    const token = async (role: string) => ((await (await browser("/api/v1/auth/tokens", { name: role, role })).json()) as { token: string }).token;
    return { admin: as(await token("admin")), editor: as(await token("editor")), viewer: as(await token("viewer")) };
  }

  return { ...t, auth, base, admin, get, send, close, roles };
}

export function totp(secret: string) {
  const bits = [...secret].map((c) => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c).toString(2).padStart(5, "0")).join("");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const mac = createHmac("sha1", key).update(counter).digest();
  return String((mac.readUInt32BE(mac[19]! & 15) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}
