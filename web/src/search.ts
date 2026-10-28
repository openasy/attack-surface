// What the search window (Cmd+K) finds in Attack Surface: assets by their name or address, and domains. They are read
// whole and filtered here.
import type { SearchFn, SearchResult } from "@openasy/ui";
import { Globe, Server } from "lucide-react";
import type { Asset, Domain } from "./api.ts";
import type { T } from "./i18n.ts";

type Call = <R>(path: string, init?: RequestInit) => Promise<R>;

export function search(call: Call, t: T): SearchFn {
  return async (q, signal) => {
    const [{ assets }, { domains }] = await Promise.all([
      call<{ assets: Asset[] }>("/api/v1/assets", { signal }),
      call<{ domains: Domain[] }>("/api/v1/domains", { signal }),
    ]);
    const found: SearchResult[] = domains
      .filter((d) => d.name.includes(q))
      .slice(0, 3)
      .map((d) => ({ id: `domain:${d.id}`, label: d.name, detail: t(`domainStates.${d.state}`), kind: t("search.domain"), icon: Globe, href: "/domains" }));
    return [
      ...found,
      ...assets
        .filter((a) => `${a.key} ${a.addresses.join(" ")}`.toLowerCase().includes(q))
        .slice(0, 8 - found.length)
        .map((a): SearchResult => ({
          id: `asset:${a.key}`,
          label: a.key,
          detail: a.ports.length ? a.ports.join(", ") : a.addresses.join(", "),
          kind: t("search.asset"),
          icon: Server,
          severity: a.worst ?? undefined,
          href: `/assets?key=${encodeURIComponent(a.key)}`,
        })),
    ];
  };
}
