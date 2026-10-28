import { describe, expect, it } from "vitest";
import { certDays, exposures } from "./rules.ts";
import type { ServiceObs, Snapshot } from "./scan.ts";
import { http, T0, tls } from "./test-app.ts";

const DAY = 86_400_000;
const service = (port: number, over: Partial<ServiceObs> = {}): ServiceObs => ({
  asset: "www.example.com",
  root: "example.com",
  address: "198.51.100.10",
  port,
  service: "x",
  banner: null,
  tls: null,
  legacyTls: null,
  http: null,
  ...over,
});
const snap = (over: Partial<Snapshot>): Snapshot => ({ domains: [], assets: [], services: [], outside: [], warnings: [], probes: 0, ...over });
const rules = (s: Snapshot) => exposures(s, T0).map((e) => [e.rule, e.severity, e.title]);

describe("exposures", () => {
  it("call out databases, remote access and the Docker API", () => {
    expect(
      rules(snap({ services: [service(5432), service(3389), service(2375), service(445), service(21), service(22, { banner: "SSH-2.0-OpenSSH_9.6" })] })),
    ).toEqual([
      ["database-exposed", "high", "PostgreSQL open to the internet"],
      ["remote-access-exposed", "high", "Remote Desktop (RDP) open to the internet"],
      ["docker-api-exposed", "critical", "Docker API without TLS"],
      ["smb-exposed", "high", "SMB open to the internet"],
      ["ftp-exposed", "medium", "FTP open to the internet"],
      ["ssh-exposed", "low", "SSH open to the internet"],
    ]);
  });

  it("read the certificate: expired, expiring, for another name, untrusted, weak, old protocols", () => {
    const at = (days: number) => new Date(T0 + days * DAY).toISOString();
    expect(rules(snap({ services: [service(443, { tls: tls({ notAfter: at(-2) }) })] }))).toEqual([["tls-expired", "critical", "Certificate expired"]]);
    expect(rules(snap({ services: [service(443, { tls: tls({ notAfter: at(5) }) })] }))).toEqual([["tls-expiring", "high", "Certificate expires in 5 days"]]);
    expect(rules(snap({ services: [service(443, { tls: tls({ notAfter: at(20) }) })] }))).toEqual([
      ["tls-expiring", "medium", "Certificate expires in 20 days"],
    ]);
    expect(rules(snap({ services: [service(443, { tls: tls({ notAfter: at(40) }) })] }))).toEqual([]);
    expect(
      rules(
        snap({
          services: [
            service(443, {
              tls: tls({ nameMatches: false, trusted: false, selfSigned: true, trustError: "DEPTH_ZERO_SELF_SIGNED_CERT", keyType: "rsa", keyBits: 1024 }),
              legacyTls: true,
            }),
          ],
        }),
      ),
    ).toEqual([
      ["tls-name-mismatch", "medium", "Certificate is for another name"],
      ["tls-untrusted", "medium", "Self-signed certificate"],
      ["tls-weak-key", "medium", "Weak certificate key"],
      ["tls-legacy", "medium", "TLS 1.0 or 1.1 accepted"],
    ]);
  });

  it("read the page: plain HTTP, a login, versions and missing headers", () => {
    const page = http({ headers: { "content-type": "text/html; charset=utf-8", server: "nginx/1.18.0" }, title: "Grafana", login: true });
    expect(rules(snap({ services: [service(80, { http: page })] }))).toEqual([
      ["http-only", "medium", "Served over plain HTTP"],
      ["login-page", "medium", "Login page open to the internet"],
      ["version-disclosed", "info", "Software version in headers"],
      ["headers-missing", "low", "Security headers missing"],
    ]);
    expect(exposures(snap({ services: [service(443, { tls: tls(), http: http({ headers: { "content-type": "text/html" } }) })] }), T0)[0]!.detail).toBe(
      "Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options or frame-ancestors",
    );
    expect(rules(snap({ services: [service(80, { http: http({ status: 301, headers: { location: "https://www.example.com/" } }) })] }))).toEqual([]);
    expect(rules(snap({ services: [service(80, { http: http({ status: 302, headers: { location: "http://www.example.com/x" } }) })] }))).toEqual([
      ["http-only", "medium", "Redirect stays on plain HTTP"],
    ]);
    expect(rules(snap({ services: [service(443, { tls: tls(), http: http() })] }))).toEqual([]);
  });

  it("read DNS: a dangling CNAME, a private address, mail without SPF or DMARC", () => {
    const records = { a: [], aaaa: [], mx: ["mail.example.com"], ns: [], spf: null, dmarc: "v=DMARC1; p=none", caa: [] };
    const asset = {
      kind: "name" as const,
      root: "example.com",
      addresses: [],
      sources: ["certificate"],
      probed: null,
      cname: null,
      note: null,
      dangling: false,
    };
    expect(
      rules(
        snap({
          domains: [{ name: "example.com", records }],
          assets: [
            { ...asset, key: "docs-old.example.com", cname: "acme.s3-website.example-cloud.net", dangling: true },
            { ...asset, key: "intranet.example.com", addresses: ["10.0.4.2"], note: "10.0.4.2 is a private address." },
          ],
        }),
      ),
    ).toEqual([
      ["spf-missing", "low", "No SPF record"],
      ["dmarc-none", "info", "DMARC policy is none"],
      ["caa-missing", "info", "No CAA record"],
      ["dangling-cname", "high", "CNAME to a name that does not resolve"],
      ["private-address", "low", "Public name on a private address"],
    ]);
  });

  it("are the same exposure across scans", () => {
    const a = exposures(snap({ services: [service(5432)] }), T0)[0]!;
    const b = exposures(snap({ services: [service(5432, { banner: "changed" })] }), T0 + DAY)[0]!;
    expect(a.id).toBe(b.id);
    expect(a.id).not.toBe(exposures(snap({ services: [service(3306)] }), T0)[0]!.id);
  });
});

describe("certificate thresholds", () => {
  it("are OPENASY_CERT_WARN_DAYS, shared with Certificates and Uptime", () => {
    expect(certDays(undefined)).toEqual({ warn: 30, critical: 7, steps: [30, 14, 7, 1, 0] });
    expect(certDays("60, 21,x")).toEqual({ warn: 60, critical: 7, steps: [60, 21, 0] });
    expect(certDays("5,2")).toEqual({ warn: 5, critical: 5, steps: [5, 2, 0] });
  });
});
