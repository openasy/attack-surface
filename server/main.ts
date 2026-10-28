import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createAuth, oidcFromEnv, readSecretsKey } from "@openasy/auth";
import { createApp, createMetricsHandler } from "./app.ts";
import { crtSh } from "./ct.ts";
import { openDb } from "./db.ts";
import { systemDns } from "./dns.ts";
import { log } from "./log.ts";
import { createLimiter, createProber } from "./probe.ts";
import { parseProducts } from "./products.ts";
import { certDays } from "./rules.ts";
import { DEFAULT_PORTS } from "./scan.ts";
import { createSurface } from "./surface.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const port = Number(process.env.PORT ?? 8080);
const dbPath = process.env.ATTACK_SURFACE_DB ?? "/data/attack-surface.db";
const scanHours = Number(process.env.ATTACK_SURFACE_SCAN_HOURS ?? 24);
const rate = Number(process.env.ATTACK_SURFACE_RATE ?? 10);
const ports = (process.env.ATTACK_SURFACE_PORTS ?? DEFAULT_PORTS.join(",")).split(",").map((p) => Number(p.trim()));
const ctUrl = process.env.ATTACK_SURFACE_CT_URL ?? "https://crt.sh/";
const dnsServers = (process.env.ATTACK_SURFACE_DNS_SERVERS ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
// For a lab or a test network only: lets private addresses be ranges and be probed. Loopback, link-local and
// multicast addresses are refused whatever it says (scope.ts).
const allowPrivate = process.env.ATTACK_SURFACE_ALLOW_PRIVATE === "true";
const webDir = new URL("../dist/web", import.meta.url).pathname;
const docsDir = new URL("../dist/docs", import.meta.url).pathname;
const openapi = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Record<string, unknown>;
const headless = process.env.ATTACK_SURFACE_HEADLESS === "true";
// Set it to keep /metrics off the port that is published or behind an ingress (ADR 0026).
const metricsPort = process.env.ATTACK_SURFACE_METRICS_PORT ? Number(process.env.ATTACK_SURFACE_METRICS_PORT) : undefined;

if (!Number.isFinite(scanHours) || scanHours < 1 || scanHours > 168) throw new Error("ATTACK_SURFACE_SCAN_HOURS must be a number of hours, 1 to 168");
if (!Number.isFinite(rate) || rate < 1 || rate > 100) throw new Error("ATTACK_SURFACE_RATE must be a number of connections a second, 1 to 100");
if (!ports.length || ports.length > 100 || ports.some((p) => !Number.isInteger(p) || p < 1 || p > 65535) || new Set(ports).size !== ports.length)
  throw new Error("ATTACK_SURFACE_PORTS must be up to 100 different port numbers, such as 22,80,443");
if (ctUrl !== "off" && !/^https?:\/\//.test(ctUrl)) throw new Error("ATTACK_SURFACE_CT_URL must be an http(s) address, or off");

const db = openDb(dbPath);
// The address people open Attack Surface at, behind the TLS proxy (ADR 0026). Cookies, passkeys and OIDC redirects use it.
const publicUrl = (process.env.ATTACK_SURFACE_PUBLIC_URL ?? `http://localhost:${port}`).replace(/\/$/, "");
const secretsKeyFile = process.env.ATTACK_SURFACE_SECRETS_KEY_FILE ?? "/run/secrets/openasy-kek";
const secretsKey = readSecretsKey(secretsKeyFile);
const auth = createAuth({
  db,
  product: "attack-surface",
  productName: "OpenAsy Attack Surface",
  origin: publicUrl,
  // Locally the same Attack Surface is often opened as 127.0.0.1 too.
  trustedOrigins: publicUrl.startsWith("http://localhost:") ? [publicUrl.replace("localhost", "127.0.0.1")] : [],
  passwords: process.env.ATTACK_SURFACE_PASSWORD_SIGN_IN !== "false",
  oidc: oidcFromEnv(process.env, "ATTACK_SURFACE_"),
  secretsKey,
  // Audit log (ADR 0013): every sign-in, failure and change to members and tokens.
  onEvent: (event) => log(event.type === "sign-in-failed" ? "warn" : "info", "auth", { event }),
});
const products = parseProducts(process.env.OPENASY_PRODUCTS);
if (products.invalid.length) log("warn", "OPENASY_PRODUCTS: left out entries that are not id=https://address", { entries: products.invalid });

// Every request a scan makes names OpenAsy, so whoever reads their logs knows who it was and where to ask.
const userAgent = `OpenAsy-AttackSurface/${version} (+https://openasy.github.io/products/attack-surface)`;
const surface = createSurface(db, {
  dns: systemDns(dnsServers),
  ct: ctUrl === "off" ? null : crtSh(ctUrl, userAgent),
  prober: createProber({ userAgent }),
  limit: createLimiter(rate, Math.min(20, rate * 2)),
  ports,
  allowPrivate,
  scanHours,
  ratePerSecond: rate,
  certDays: certDays(process.env.OPENASY_CERT_WARN_DAYS),
});
surface.recover();
const server = createServer(
  createApp({
    db,
    surface,
    version,
    auth,
    webDir: !headless && existsSync(webDir) ? webDir : undefined,
    docsDir: existsSync(docsDir) ? docsDir : undefined,
    openapi,
    serveMetrics: metricsPort === undefined,
    products: products.products,
  }),
);
const metricsServer = metricsPort !== undefined ? createServer(createMetricsHandler(surface, version)) : undefined;
metricsServer?.listen(metricsPort, () => log("info", "metrics on their own port", { port: metricsPort }));

server.listen(port, () =>
  log("info", "attack-surface started", { version, port, db: dbPath, headless, scanHours, rate, ports: ports.length, ct: ctUrl, allowPrivate }),
);
if (!publicUrl.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(publicUrl)) {
  log("warn", "ATTACK_SURFACE_PUBLIC_URL is not https: browsers will not keep secure cookies or allow passkeys. Put Attack Surface behind TLS (ADR 0026)", {
    url: publicUrl,
  });
}
if (allowPrivate) log("warn", "ATTACK_SURFACE_ALLOW_PRIVATE is on: ranges and names on private addresses are probed. Leave it off outside a lab");
if (!secretsKey) log("warn", "no secrets key: sign-in secrets are not encrypted. Mount a 32-byte key (openssl rand -hex 32)", { file: secretsKeyFile });
const setup = auth.setupLink();
// No default password (ADR 0013): the first person to open this link becomes the owner.
if (setup) log("info", "no owner yet: open this link once to create the owner account", { url: setup });

// The schedule, asked every minute: a scan when the last one is older than ATTACK_SURFACE_SCAN_HOURS, or when a
// domain was verified or a range added since.
const tick = () => {
  if (surface.due()) surface.startScan("schedule", null);
};
surface.purge();
const timers: NodeJS.Timeout[] = [setInterval(() => auth.purge(), 5 * 60_000), setInterval(() => surface.purge(), 3_600_000), setInterval(tick, 60_000)];

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  for (const t of timers) clearInterval(t);
  metricsServer?.close();
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
