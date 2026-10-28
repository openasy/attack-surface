import { createServer as createHttp } from "node:http";
import { createServer as createHttps } from "node:https";
import { createServer as createTcp, type AddressInfo, type Server } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createLimiter, createProber } from "./probe.ts";
import { inDays, makeCert } from "./testcert.ts";

const servers: Server[] = [];
const listen = async (server: Server) => {
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return (server.address() as AddressInfo).port;
};
const prober = createProber({ userAgent: "OpenAsy-AttackSurface/test", timeoutMs: 2000, bannerMs: 200 });
const seen: Array<Record<string, unknown>> = [];
let ssh = 0;
let silent = 0;
let closed = 0;
let web = 0;
let secure = 0;
let legacy = 0;

beforeAll(async () => {
  ssh = await listen(createTcp((s) => s.end("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n")));
  silent = await listen(createTcp(() => {}));
  closed = await listen(createTcp());
  servers.pop()!.close();
  web = await listen(
    createHttp((req, res) => {
      seen.push({ method: req.method, url: req.url, ...req.headers });
      res.writeHead(200, { "content-type": "text/html", server: "nginx/1.18.0", "x-frame-options": "DENY", "set-cookie": "s=1" });
      res.end("<html><head><title> Admin \n sign in </title></head><form><input name=u><input type='password' name=p></form></html>");
    }),
  );
  const cert = makeCert({ cn: "www.example.com", sans: ["www.example.com"], notAfter: inDays(5) });
  const key = cert.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  secure = await listen(
    createHttps({ cert: cert.pem, key }, (_req, res) =>
      res.writeHead(301, { location: "https://www.example.com/", "strict-transport-security": "max-age=63072000" }).end(),
    ),
  );
  legacy = await listen(createHttps({ cert: cert.pem, key, minVersion: "TLSv1", ciphers: "DEFAULT@SECLEVEL=0" }, (_req, res) => res.end()));
});
afterAll(() => servers.forEach((s) => s.close()));

const at = (port: number, name: string | null = null) => ({ name, address: "127.0.0.1", port });

describe("ports", () => {
  it("are open or not, with what the server says first", async () => {
    expect(await prober.port(at(ssh))).toEqual({ open: true, banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3" });
    expect(await prober.port(at(silent))).toEqual({ open: true, banner: null });
    expect(await prober.port(at(closed))).toEqual({ open: false, banner: null });
  });
});

describe("http", () => {
  it("is one GET / with OpenAsy's name, and reads headers, title and a login form", async () => {
    const r = await prober.http(at(web, "admin.example.com"), false);
    expect(r).toEqual({
      status: 200,
      headers: { "content-type": "text/html", server: "nginx/1.18.0", "x-frame-options": "DENY" },
      title: "Admin sign in",
      login: true,
    });
    expect(seen).toEqual([expect.objectContaining({ method: "GET", url: "/", host: `admin.example.com:${web}`, "user-agent": "OpenAsy-AttackSurface/test" })]);
    expect(await prober.http(at(closed), false)).toBeNull();
  });
});

describe("tls", () => {
  it("reads the certificate, whether it is trusted and for the name, and the protocol", async () => {
    const r = await prober.tls(at(secure, "www.example.com"));
    expect(r).toMatchObject({
      subject: "www.example.com",
      issuer: "www.example.com",
      sans: ["www.example.com"],
      keyType: "rsa",
      keyBits: 2048,
      protocol: "TLSv1.3",
      trusted: false,
      nameMatches: true,
      selfSigned: true,
    });
    expect(r!.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(Date.parse(r!.notAfter) - Date.now()).toBeLessThan(6 * 86_400_000);
    expect((await prober.tls(at(secure, "other.example.com")))!.nameMatches).toBe(false);
    expect(await prober.tls(at(ssh))).toBeNull();
    const https = await prober.http(at(secure, "www.example.com"), true);
    expect(https).toMatchObject({ status: 301, headers: { location: "https://www.example.com/", "strict-transport-security": "max-age=63072000" } });
  });

  it("tells a server that still takes TLS 1.0 or 1.1 from one that does not", async () => {
    expect(await prober.legacyTls(at(secure, "www.example.com"))).toBe(false);
    expect(await prober.legacyTls(at(legacy, "www.example.com"))).toBe(true);
  });
});

describe("the limiter", () => {
  it("keeps to the rate and to the connections open at once", async () => {
    const waits: number[] = [];
    const limit = createLimiter(10, 2, async (ms) => void waits.push(ms));
    let open = 0;
    let most = 0;
    await Promise.all(
      Array.from({ length: 6 }, () =>
        limit(async () => {
          most = Math.max(most, ++open);
          await new Promise((r) => setTimeout(r, 5));
          open--;
        }),
      ),
    );
    expect(most).toBe(2);
    // Six calls at ten a second: the five after the first each wait their turn.
    expect(waits.length).toBe(5);
  });
});
