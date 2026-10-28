// The only code that connects to anything a scan finds (ADR 0067). A TCP connect to see whether a port answers, and
// what a server says first; a TLS handshake to read its certificate; one GET / to read the headers. Nothing is sent
// that tries a password, a path or a payload. Every call goes to an address that scope.ts has let through, named by
// the host it belongs to, so a name that changes its answer in between is not followed.
import { createHash, X509Certificate } from "node:crypto";
import { request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { connect as tcpConnect, isIP } from "node:net";
import { checkServerIdentity, connect as tlsConnect, type PeerCertificate, type TLSSocket } from "node:tls";

export interface PortResult {
  open: boolean;
  /** What the server sent first, unasked, cut to 200 printable characters; null when it waited for us. */
  banner: string | null;
}

export interface TlsResult {
  fingerprint: string;
  subject: string | null;
  issuer: string | null;
  sans: string[];
  notBefore: string;
  notAfter: string;
  keyType: string | null;
  keyBits: number | null;
  protocol: string | null;
  /** Whether the system's roots trust the chain; why not, when they do not. */
  trusted: boolean;
  trustError: string | null;
  /** Whether the certificate is for the name the connection was for. */
  nameMatches: boolean;
  selfSigned: boolean;
}

export interface HttpResult {
  status: number;
  /** The headers the checks read, lower case. */
  headers: Record<string, string>;
  title: string | null;
  /** The page has a password field: a login screen. */
  login: boolean;
}

export interface Target {
  /** The host name the address was found for, sent as SNI and Host; null for an address from a range. */
  name: string | null;
  address: string;
  port: number;
}

export interface Prober {
  port(t: Target): Promise<PortResult>;
  tls(t: Target): Promise<TlsResult | null>;
  /** Whether a handshake that offers only TLS 1.0 and 1.1 is taken. */
  legacyTls(t: Target): Promise<boolean>;
  http(t: Target, tls: boolean): Promise<HttpResult | null>;
}

export interface ProberOptions {
  userAgent: string;
  timeoutMs?: number;
  /** How long to wait for a server that speaks first, such as SSH or SMTP. */
  bannerMs?: number;
}

const printable = (b: Buffer) =>
  b
    .toString("latin1")
    .replace(/[^\x20-\x7e]+/g, " ")
    .trim()
    .slice(0, 200) || null;

const cn = (s: Record<string, string | string[]> | undefined) => {
  const v = s?.CN ?? s?.O;
  return v === undefined ? null : Array.isArray(v) ? v.join(", ") : v;
};

/** How a probe goes out; the default is the real network. */
export function createProber({ userAgent, timeoutMs = 4000, bannerMs = 1500 }: ProberOptions): Prober {
  const servername = (t: Target) => (t.name && !isIP(t.name) ? t.name : undefined);

  const handshake = (t: Target, legacy: boolean) =>
    new Promise<TLSSocket | null>((resolve) => {
      const socket = tlsConnect({
        host: t.address,
        port: t.port,
        servername: servername(t),
        rejectUnauthorized: false,
        timeout: timeoutMs,
        ...(legacy && { minVersion: "TLSv1" as const, maxVersion: "TLSv1.1" as const, ciphers: "DEFAULT@SECLEVEL=0" }),
      });
      const fail = () => (socket.destroy(), resolve(null));
      socket.once("timeout", fail);
      socket.once("error", fail);
      socket.once("secureConnect", () => resolve(socket));
    });

  return {
    port: (t) =>
      new Promise((resolve) => {
        const socket = tcpConnect({ host: t.address, port: t.port, timeout: timeoutMs });
        const chunks: Buffer[] = [];
        let open = false;
        const done = () => {
          socket.destroy();
          resolve({ open, banner: open && chunks.length ? printable(Buffer.concat(chunks)) : null });
        };
        socket.once("connect", () => {
          open = true;
          socket.setTimeout(bannerMs);
        });
        socket.on("data", (c: Buffer) => {
          chunks.push(c);
          if (Buffer.concat(chunks).length >= 512 || c.includes(10)) done();
        });
        socket.once("timeout", done);
        socket.once("error", done);
        socket.once("end", done);
      }),

    async tls(t) {
      const socket = await handshake(t, false);
      if (!socket) return null;
      const peer = socket.getPeerCertificate(true) as PeerCertificate & { issuerCertificate?: PeerCertificate };
      const protocol = socket.getProtocol();
      const trustError = socket.authorized ? null : String(socket.authorizationError ?? "not trusted");
      socket.end();
      if (!peer?.raw) return null;
      const x509 = new X509Certificate(peer.raw);
      const key = x509.publicKey;
      const host = servername(t);
      return {
        fingerprint: createHash("sha256").update(peer.raw).digest("hex"),
        subject: cn(peer.subject as unknown as Record<string, string>),
        issuer: cn(peer.issuer as unknown as Record<string, string>),
        sans: (x509.subjectAltName ?? "")
          .split(", ")
          .filter((s) => s.startsWith("DNS:") || s.startsWith("IP Address:"))
          .map((s) => s.replace(/^DNS:|^IP Address:/, "")),
        notBefore: new Date(x509.validFrom).toISOString(),
        notAfter: new Date(x509.validTo).toISOString(),
        keyType: key.asymmetricKeyType ?? null,
        keyBits: key.asymmetricKeyDetails?.modulusLength ?? null,
        protocol,
        trusted: !trustError,
        trustError,
        nameMatches: host ? !checkServerIdentity(host, peer) : true,
        selfSigned: x509.issuer === x509.subject && x509.checkIssued(x509),
      };
    },

    async legacyTls(t) {
      const socket = await handshake(t, true);
      socket?.end();
      return Boolean(socket);
    },

    http: (t, tls) =>
      new Promise((resolve) => {
        const host = t.name ?? (isIP(t.address) === 6 ? `[${t.address}]` : t.address);
        const req = (tls ? httpsRequest : httpRequest)({
          host: t.address,
          port: t.port,
          method: "GET",
          path: "/",
          headers: { host: t.port === (tls ? 443 : 80) ? host : `${host}:${t.port}`, "user-agent": userAgent, accept: "text/html,*/*;q=0.8" },
          timeout: timeoutMs,
          ...(tls && { servername: servername(t), rejectUnauthorized: false }),
        });
        req.once("timeout", () => req.destroy(new Error("timeout")));
        req.once("error", () => resolve(null));
        req.once("response", (res: IncomingMessage) => {
          const chunks: Buffer[] = [];
          let size = 0;
          const finish = () => {
            const html = Buffer.concat(chunks).toString("utf8");
            const title = /<title[^>]*>([^<]{0,200})/i.exec(html)?.[1]?.replace(/\s+/g, " ").trim() || null;
            const headers: Record<string, string> = {};
            for (const [k, v] of Object.entries(res.headers))
              if (v !== undefined && READ.has(k)) headers[k] = (Array.isArray(v) ? v.join(", ") : v).slice(0, 500);
            resolve({ status: res.statusCode ?? 0, headers, title, login: /<input[^>]+type\s*=\s*["']?password/i.test(html) });
            req.destroy();
          };
          res.on("data", (c: Buffer) => {
            size += c.length;
            chunks.push(c);
            // Enough of the page for its title and its form; the rest is not read.
            if (size >= 64 * 1024) finish();
          });
          res.once("end", finish);
          res.once("error", finish);
        });
        req.end();
      }),
  };
}

const READ = new Set([
  "server",
  "x-powered-by",
  "location",
  "content-type",
  "strict-transport-security",
  "content-security-policy",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
]);

/**
 * At most perSecond new connections a second and concurrency open at once, for every probe of a scan together. A
 * waiting probe is handed the place of one that ends, so the two limits hold under any load.
 */
export function createLimiter(perSecond: number, concurrency: number, sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))) {
  let active = 0;
  let next = 0;
  const waiting: Array<() => void> = [];
  const release = () => {
    const w = waiting.shift();
    if (w) w();
    else active--;
  };
  return async <T>(fn: () => Promise<T>): Promise<T> => {
    if (active >= concurrency) await new Promise<void>((r) => waiting.push(r));
    else active++;
    const now = Date.now();
    const at = Math.max(now, next);
    next = at + 1000 / perSecond;
    if (at > now) await sleep(at - now);
    try {
      return await fn();
    } finally {
      release();
    }
  };
}
export type Limiter = ReturnType<typeof createLimiter>;
