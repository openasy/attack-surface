// Names from certificate transparency: every public certificate is logged, so the names a domain's certificates were
// issued for are its subdomains, the forgotten ones too. Read from crt.sh's JSON, one request per verified domain,
// never anything else of the domain's (ADR 0067).
import { hostName } from "./scope.ts";

export interface CtName {
  name: string;
  /** The last day a certificate for it was valid, as the log has it. */
  notAfter: string | null;
}

/** Names logged for certificates under a domain, wildcards with their *. taken off. */
export type CtSource = (domain: string) => Promise<CtName[]>;

/** At most this many log rows are read for one domain; crt.sh returns every certificate ever issued. */
const MAX_ROWS = 20_000;

/** Reads crt.sh's JSON: rows with name_value (names, one a line), common_name and not_after. */
export function parseCrtSh(body: unknown): CtName[] {
  if (!Array.isArray(body)) throw new Error("The certificate transparency answer is not a list.");
  const names = new Map<string, string | null>();
  for (const row of body.slice(0, MAX_ROWS) as Array<Record<string, unknown>>) {
    if (!row || typeof row !== "object") continue;
    const notAfter = typeof row.not_after === "string" ? row.not_after : null;
    const raw = [typeof row.name_value === "string" ? row.name_value : "", typeof row.common_name === "string" ? row.common_name : ""].join("\n");
    for (const line of raw.split(/\s+/)) {
      const name = hostName(line.replace(/^\*\./, ""));
      if (!name) continue;
      const before = names.get(name);
      if (before === undefined || (notAfter && (!before || notAfter > before))) names.set(name, notAfter);
    }
  }
  return [...names].map(([name, notAfter]) => ({ name, notAfter }));
}

/** crt.sh, or a service that answers the same way at base. */
export function crtSh(base: string, userAgent: string, timeoutMs = 60_000): CtSource {
  return async (domain) => {
    const url = new URL(base);
    url.searchParams.set("q", `%.${domain}`);
    url.searchParams.set("output", "json");
    const res = await fetch(url, {
      headers: { accept: "application/json", "user-agent": userAgent },
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`${url.host} answered ${res.status} for ${domain}.`);
    return parseCrtSh(await res.json());
  };
}
