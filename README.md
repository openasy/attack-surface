# attack-surface

[![CI](https://github.com/openasy/attack-surface/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/attack-surface/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) Attack Surface product: **everything you expose to the internet, including
what you forgot** (ADR 0067). Attackers start with what they can reach: a forgotten staging subdomain, a database port
opened for a test, an expired certificate on an old mail server. Attack Surface starts from the domains you have proven
are yours, finds their names in DNS and certificate transparency, checks what answers on a short list of ports, and
tells you what appeared, went or changed since the last scan.

```
example.com ──TXT proof──▶ attack-surface ──DNS, crt.sh──▶ names under example.com ──connect, TLS, GET /──▶ Changes,
203.0.113.0/28 (an admin,                       │                                                         Assets, Exposures,
  with a reason)                                └──▶ names outside: listed, never touched                 Certificates
                                                                                                 └──▶ /metrics ──▶ Alerts
```

## Only what you own

This is a defensive tool, and its first rule is that it never touches anything that is not yours:

- **A domain is scanned only once its owner proves it**, as Let's Encrypt or Google ask: Attack Surface gives a random
  token, and the domain is verified when `_openasy-attack-surface.example.com` has the TXT record
  `openasy-attack-surface-verification=<token>`. Every scan reads the record again first; a domain whose record has
  gone is marked lost and is not scanned until it is back.
- **An address range is added only by an admin, with a reason**, such as the provider and the contract, which the
  audit log keeps with their name. A range is at most 256 addresses (a /24 or a /120) and may not overlap another.
  Private addresses are refused unless `ATTACK_SURFACE_ALLOW_PRIVATE=true`, for a lab; loopback, link-local (cloud
  metadata) and multicast addresses are refused always.
- **Names outside the verified domains are shown, and left alone.** A certificate for `www.example.com` that also
  names `partner-portal.com`, a CNAME to a cloud bucket, a mail server at Google: each is listed under Domains, and
  never resolved or connected to.
- **Every connection passes one check first** (`assertProbe` in `server/scope.ts`): the name must be under a verified
  domain, or the address in a range, and the address must not be refused. A name that resolves to a private address
  is noted and not probed.

## What a scan does

Every day (`ATTACK_SURFACE_SCAN_HOURS`), and soon after a domain is verified or a range is added:

- **Discovery, passive only.** The DNS records of each verified domain (A, AAAA, MX, NS, SPF, DMARC, CAA), and the names
  its certificates were issued for, from [crt.sh](https://crt.sh/). Each name is resolved; a name that resolves to
  nothing is history, not an asset, unless a CNAME still points away from it. No name is guessed: no word lists, no
  brute force, no zone transfers.
- **A light check of what answers.** A TCP connect to 30 common ports (`ATTACK_SURFACE_PORTS`), no SYN or stealth
  scan, at most 10 new connections a second for the whole scan (`ATTACK_SURFACE_RATE`). What a server says first is
  kept as its banner. On TLS ports, a handshake reads the certificate, and a second one offering only TLS 1.0 and 1.1
  tells whether they are still taken. On web ports, one `GET /` reads the status, the headers and the title. Each
  address and port is connected to once a scan, however many names point there.
- **Nothing more.** No password is tried, no path is guessed, no payload is sent and no vulnerability is probed for.
  Every request names itself: `User-Agent: OpenAsy-AttackSurface/0.1.0 (+https://openasy.github.io/products/attack-surface)`.
  Testing an application is DAST's work (ADR 0037).

## What it shows

- **Changes**, the first screen: a new host, a new open port, a port closed, addresses changed, a certificate replaced
  or about to expire, an exposure new or resolved. Editors acknowledge them. A certificate is reported once each time
  it crosses a threshold of `OPENASY_CERT_WARN_DAYS` (30, 14, 7, 1 and 0 days by default, ADR 0052), not every scan.
- **Assets**: host names and addresses that answer, their open ports, where they were found and when first seen.
- **Exposures**: a database, Redis, Elasticsearch or the Docker API open to the internet; RDP, VNC, Telnet, SMB, FTP
  and SSH; an expired, expiring, self-signed or mismatched certificate, a weak key, TLS 1.0 or 1.1; a site on plain
  HTTP, a login page anyone can try, missing security headers, a version in the headers; a dangling CNAME (a takeover
  candidate), a public name on a private address, mail without SPF or DMARC.
- **Certificates**: every certificate presented, once, with where it was seen and how long it has left.
- **Domains**: the verified domains with their records and the TXT record to publish, the ranges and their reasons,
  and the names seen outside.
- **Scans**: each scan, what it covered, how many connections it made and what went wrong along the way.

## Run

```bash
openssl rand -hex 32 > openasy-kek
docker compose up -d
docker compose logs attack-surface | grep 'no owner yet'
```

Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080, the API reference at http://localhost:8080/api/docs/. Add a domain under Domains,
publish its TXT record and verify it; the first scan starts within a minute.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `ATTACK_SURFACE_PUBLIC_URL` | `http://localhost:8080` | The address people open, with `https://` behind your TLS proxy |
| `ATTACK_SURFACE_SCAN_HOURS` | `24` | Hours between scans, 1 to 168 |
| `ATTACK_SURFACE_RATE` | `10` | New connections a second, for a whole scan, 1 to 100 |
| `ATTACK_SURFACE_PORTS` | 30 common ports | The ports checked, up to 100, such as `22,80,443` |
| `ATTACK_SURFACE_CT_URL` | `https://crt.sh/` | Certificate transparency search with crt.sh's JSON, or `off` |
| `ATTACK_SURFACE_DNS_SERVERS` | the system's | Resolvers to ask, such as `1.1.1.1,9.9.9.9` |
| `ATTACK_SURFACE_ALLOW_PRIVATE` | `false` | `true` lets ranges and names on private addresses be probed, for a lab |
| `OPENASY_CERT_WARN_DAYS` | `30,14,7,1` | When certificates warn, as in Certificates and Uptime |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher |
| `ATTACK_SURFACE_SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key for sign-in secrets |
| `ATTACK_SURFACE_DB` | `/data/attack-surface.db` | SQLite file (WAL), on the `/data` volume |
| `ATTACK_SURFACE_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `ATTACK_SURFACE_HEADLESS` | `false` | `true` serves only the API |
| `ATTACK_SURFACE_PASSWORD_SIGN_IN`, `OPENASY_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)) |

Attack Surface keeps no secret of its own: the TXT token is published in DNS, and no target needs a password. The
key seals the sign-in secrets of `@openasy/auth` (ADR 0021).

`/metrics` has `openasy_attack_surface_domains` by state, `openasy_attack_surface_ranges`,
`openasy_attack_surface_assets`, `openasy_attack_surface_services`, `openasy_attack_surface_exposures` by severity,
`openasy_attack_surface_certificates_expiring`, `openasy_attack_surface_changes_unacknowledged`,
`openasy_attack_surface_last_scan_timestamp_seconds` and `openasy_attack_surface_last_scan_success`. Fire on a new
critical exposure in Alerts.

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`: a connect
check needs no raw socket.

## Roles

Viewers see everything; editors also add and verify domains, start scans and acknowledge changes; admins also delete
domains, add and delete ranges, read the audit log, and manage members and API tokens (ADR 0003). Every domain and
range added, verified, lost or deleted, and every scan started by someone, is written to an append-only audit log in
SQLite and to the log as an audit event (ADR 0013).

## Not yet

Not in 0.1.0: links to the products named on the site (a web application to DAST as a target, certificates to
Certificates, services to Vulnerabilities), the domains' registration and expiry (RDAP), look-alike domains, reverse
DNS of the ranges, owners of assets, cloud provider names, more than one address of a name probed, IPv6 ranges larger
than a /120, scan settings in the UI rather than in the environment, and stopping a running scan. The endpoints file
(`OPENASY_ENDPOINTS`, ADR 0052) is not read yet, so an asset is not marked as known when the inventory lists it.

## Develop

```bash
npm install
npm test        # scope, discovery, probes against servers on 127.0.0.1, rules, changes, roles, and every API response against openapi.json
npm run dev     # the UI, with the API on :8080
node scripts/openapi.ts   # after changing the API
```

The tests never scan the internet: DNS and certificate transparency are fakes, and every probe goes to a server the
test starts on this machine.

## Licence

AGPL-3.0 (ADR 0008).
