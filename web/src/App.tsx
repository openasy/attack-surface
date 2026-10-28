import {
  AppShell,
  Badge,
  BarList,
  BrandProvider,
  Button,
  Callout,
  DataTable,
  Dialog,
  EmptyState,
  EntityChip,
  formatNumber,
  IconButton,
  KpiCard,
  KpiGrid,
  navigate,
  OverviewGrid,
  PageHeader,
  Panel,
  PRODUCT_IDS,
  SearchInput,
  SegmentedControl,
  SeverityBadge,
  StatusBadge,
  TextField,
  toLocale,
  useLocalePreference,
  usePath,
  useThemePreference,
  type Column,
  type ProductId,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAccountMenu, useAuth, useInstallBrand } from "@openasy/auth/react";
import colophon from "virtual:openasy-colophon";
import {
  BadgeCheck,
  Boxes,
  Check,
  GitCompare,
  Globe,
  KeyRound,
  LogIn,
  LogOut,
  Network,
  Play,
  Plus,
  Radar,
  RefreshCw,
  ScrollText,
  ShieldCheck,
  Trash2,
  TriangleAlert,
  UserRound,
  Users,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  MfaSetupRequired,
  Unauthorized,
  type AssetDetail,
  type Asset,
  type AuditEntry,
  type Certificate,
  type Change,
  type Domain,
  type Exposure,
  type Outside,
  type ProductLink,
  type Range,
  type Scan,
  type Severity,
  type Summary,
} from "./api.ts";
import { useT, type T } from "./i18n.ts";
import { search } from "./search.ts";

const PAGES = ["assets", "exposures", "certificates", "domains", "scans", "audit", "account", "members", "signin", "tokens"] as const;
type Page = "changes" | (typeof PAGES)[number];
/** The first path segments that are pages of this UI, for followLinks. */
export const PATHS = ["changes", ...PAGES];
function parsePage(path: string): Page {
  const page = path.replace(/^\//, "").split("/")[0] ?? "";
  return (PAGES as readonly string[]).includes(page) ? (page as Page) : "changes";
}

/** A query parameter of the address. */
const param = (name: string) => new URLSearchParams(window.location.search).get(name);

/** Data loading with the session; when it ends, the sign-in screen comes back. */
function useApi() {
  const { expired, refresh } = useAuth();
  return useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      try {
        return await api<T>(path, init);
      } catch (err) {
        if (err instanceof Unauthorized) expired();
        if (err instanceof MfaSetupRequired) void refresh();
        throw err;
      }
    },
    [expired, refresh],
  );
}
type Call = ReturnType<typeof useApi>;

/** Loads a path now, again every `every` ms when set, and on demand; keeps its error to show. */
function useLoad<T>(call: Call, path: string | null, every?: number) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string>();
  const load = useCallback(() => {
    if (!path) return;
    void call<T>(path).then(
      (d) => (setData(d), setError(undefined)),
      (err: Error) => setError(err.message),
    );
  }, [call, path]);
  useEffect(() => {
    load();
    if (!every) return;
    const t = setInterval(load, every);
    return () => clearInterval(t);
  }, [load, every]);
  return [data, error, load] as const;
}

/** Runs an action, then reloads; keeps its error to show. */
function useAct(reload: () => void) {
  const [error, setError] = useState<string>();
  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      setError(undefined);
      reload();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  return [act, error] as const;
}

const when = (iso: string) => new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
const day = (iso: string) => new Date(iso).toLocaleDateString(undefined, { dateStyle: "medium" });
const duration = (s: Scan) => (s.finishedAt ? `${Math.max(1, Math.round((Date.parse(s.finishedAt) - Date.parse(s.startedAt)) / 1000))} s` : "–");
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function Code({ children }: { children: ReactNode }) {
  return <pre className="m-0 overflow-x-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs whitespace-pre-wrap text-fg">{children}</pre>;
}

function ErrorText({ message }: { message?: string }) {
  return message ? <p className="m-0 text-xs text-danger">{message}</p> : null;
}

function Host({ value }: { value: string }) {
  return (
    <EntityChip
      kind={/^[\d.:a-f]+$/.test(value) && !/^[a-f]+$/.test(value) ? "ip" : "host"}
      value={value}
      hideKind
      href={`/assets?key=${encodeURIComponent(value)}`}
    />
  );
}

const KIND_TONE = { added: "info", removed: "neutral", changed: "warning" } as const;

/** Nothing is scanned until a domain is verified or a range added; the pages say so first. */
function NoRoots({ summary }: { summary: Summary }) {
  const t = useT();
  if (summary.domains.verified || summary.ranges) return null;
  return (
    <Callout
      tone="info"
      title={t("product.noRoots")}
      action={
        <Button size="sm" variant="primary" icon={<Globe />} onClick={() => navigate("/domains")}>
          {t("product.domains")}
        </Button>
      }
    >
      {summary.domains.pending ? t("product.noRootsPending", { count: summary.domains.pending }) : t("product.noRootsDetail")}
    </Callout>
  );
}

// ---------------------------------------------------------------- Changes

function ChangesPage({ call, summary, reloadSummary }: { call: Call; summary: Summary; reloadSummary: () => void }) {
  const t = useT();
  const { can } = useAuth();
  // A link from Scans opens the changes of that one scan.
  const scan = param("scan");
  const [days, setDays] = useState<"7" | "30" | "90">("7");
  const [show, setShow] = useState<"review" | "all">(scan ? "all" : "review");
  const [data, loadError, reload] = useLoad<{ changes: Change[] }>(
    call,
    scan ? `/api/v1/changes?scan=${encodeURIComponent(scan)}` : `/api/v1/changes?days=${days}`,
    30_000,
  );
  const [act, error] = useAct(() => (reload(), reloadSummary()));
  const rows = (data?.changes ?? []).filter((c) => show === "all" || !c.acknowledgedAt);
  const columns: Column<Change>[] = [
    {
      id: "at",
      header: t("changesPage.when"),
      width: "150px",
      sortValue: (c) => c.at,
      cell: (c) => <span className="text-xs whitespace-nowrap text-fg-muted">{when(c.at)}</span>,
    },
    { id: "kind", header: t("changesPage.change"), width: "110px", cell: (c) => <Badge tone={KIND_TONE[c.kind]}>{t(`changeKinds.${c.kind}`)}</Badge> },
    {
      id: "what",
      header: t("changesPage.what"),
      width: "34%",
      cell: (c) => (
        <span className="flex min-w-0 items-start gap-2">
          {c.severity && <SeverityBadge severity={c.severity} compact />}
          <span className="flex min-w-0 flex-col">
            <span className="text-sm">{c.what}</span>
            {/* An exposure's detail says what was seen; it reads as a sentence, not as a value. */}
            {c.subject === "exposure" && c.after && <span className="as-wrap text-xs text-fg-muted">{c.after}</span>}
          </span>
        </span>
      ),
    },
    { id: "asset", header: t("changesPage.asset"), sortValue: (c) => c.asset, cell: (c) => <Host value={c.asset} /> },
    { id: "port", header: t("changesPage.port"), width: "80px", mono: true, align: "right", cell: (c) => c.port ?? "–" },
    { id: "before", header: t("changesPage.before"), cell: (c) => <span className="as-wrap font-mono text-xs text-fg-muted">{c.before ?? "–"}</span> },
    {
      id: "after",
      header: t("changesPage.after"),
      cell: (c) => <span className="as-wrap font-mono text-xs">{(c.subject !== "exposure" && c.after) || "–"}</span>,
    },
    {
      id: "ack",
      header: <span className="sr-only">{t("changesPage.acknowledge")}</span>,
      label: t("changesPage.acknowledge"),
      width: "150px",
      align: "right",
      hideable: false,
      cell: (c) =>
        c.acknowledgedAt ? (
          <span className="text-2xs text-fg-muted">{t("changesPage.acknowledgedBy", { name: c.acknowledgedBy ?? "" })}</span>
        ) : can("editor") ? (
          <Button size="xs" icon={<Check />} onClick={() => void act(() => call(`/api/v1/changes/${c.id}/acknowledge`, { method: "POST" }))}>
            {t("changesPage.acknowledge")}
          </Button>
        ) : null,
    },
  ];
  const last = summary.lastScan;
  return (
    <>
      <PageHeader
        title={t("changesPage.changes")}
        description={t("changesPage.description")}
        actions={
          <>
            <SegmentedControl
              label={t("changesPage.range")}
              value={days}
              onChange={setDays}
              options={(["7", "30", "90"] as const).map((d) => ({ value: d, label: t("changesPage.days", { count: Number(d) }) }))}
            />
            <SegmentedControl
              label={t("changesPage.show")}
              value={show}
              onChange={setShow}
              options={[
                { value: "review", label: t("changesPage.review") },
                { value: "all", label: t("changesPage.all") },
              ]}
            />
          </>
        }
      />
      <NoRoots summary={summary} />
      <KpiGrid minWidth={170}>
        <KpiCard
          label={t("changesPage.toReview")}
          value={formatNumber(summary.unacknowledged)}
          icon={GitCompare}
          tone={summary.unacknowledged ? "warning" : "success"}
        />
        <KpiCard label={t("changesPage.newAssets")} value={summary.newAssets} unit={t("changesPage.lastWeek")} icon={Boxes} href="/assets" />
        <KpiCard
          label={t("changesPage.serious")}
          value={summary.exposures.critical + summary.exposures.high}
          icon={TriangleAlert}
          tone={summary.exposures.critical ? "critical" : summary.exposures.high ? "danger" : "success"}
          href="/exposures"
        />
        <KpiCard
          label={t("changesPage.expiring")}
          value={summary.certificates.expiring + summary.certificates.expired}
          unit={t("changesPage.withinDays", { count: summary.settings.certWarnDays })}
          icon={BadgeCheck}
          tone={summary.certificates.expired ? "critical" : summary.certificates.expiring ? "warning" : undefined}
          href="/certificates"
        />
      </KpiGrid>
      {last?.state === "failed" && (
        <Callout tone="danger" title={t("changesPage.lastFailed")}>
          {last.error}
        </Callout>
      )}
      <ErrorText message={error ?? loadError} />
      <Panel
        title={scan ? t("changesPage.ofScan") : t("changesPage.panel", { count: Number(days) })}
        description={last ? t("changesPage.lastScan", { when: when(last.startedAt), count: rows.length }) : t("changesPage.noScan")}
        flush
      >
        <DataTable
          label={t("changesPage.changes")}
          columns={columns}
          rows={rows}
          loading={!data}
          getRowId={(c) => String(c.id)}
          minWidth={1100}
          empty={<EmptyState title={show === "review" ? t("changesPage.noneToReview") : t("changesPage.none")}>{t("changesPage.noneDetail")}</EmptyState>}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Assets

function AssetDialog({ call, assetKey, onClose }: { call: Call; assetKey: string | null; onClose: () => void }) {
  const t = useT();
  const [a] = useLoad<AssetDetail>(call, assetKey ? `/api/v1/assets/${encodeURIComponent(assetKey)}` : null);
  const shown = a && a.key === assetKey ? a : undefined;
  return (
    <Dialog
      open={assetKey !== null}
      onOpenChange={(open) => !open && onClose()}
      title={assetKey ?? ""}
      description={shown && t("assetsPage.detail", { root: shown.root })}
      size="lg"
    >
      {!shown ? (
        <EmptyState title={t("product.loading")} />
      ) : (
        <div className="flex flex-col gap-3">
          <dl className="as-facts text-sm">
            <dt className="text-fg-muted">{t("assetsPage.addresses")}</dt>
            <dd className="font-mono text-xs">{shown.addresses.join(", ") || "–"}</dd>
            {shown.cname && (
              <>
                <dt className="text-fg-muted">CNAME</dt>
                <dd className="font-mono text-xs">{shown.cname}</dd>
              </>
            )}
            <dt className="text-fg-muted">{t("assetsPage.foundIn")}</dt>
            <dd>{shown.sources.map((s) => t(`sources.${s}`)).join(", ")}</dd>
            <dt className="text-fg-muted">{t("assetsPage.firstSeen")}</dt>
            <dd>{when(shown.firstSeen)}</dd>
            <dt className="text-fg-muted">{t("assetsPage.lastSeen")}</dt>
            <dd>{when(shown.lastSeen)}</dd>
          </dl>
          {shown.note && (
            <Callout tone="info" title={t("assetsPage.notProbed")}>
              {shown.note}
            </Callout>
          )}
          <Panel title={t("assetsPage.services")} flush>
            <DataTable
              label={t("assetsPage.services")}
              rows={shown.services}
              getRowId={(s) => String(s.port)}
              minWidth={640}
              empty={<EmptyState title={t("assetsPage.noServices")} />}
              columns={[
                {
                  id: "port",
                  header: t("assetsPage.port"),
                  width: "130px",
                  mono: true,
                  cell: (s) => (
                    <span className={s.goneAt ? "text-fg-muted line-through" : undefined}>
                      {s.port}/{s.service}
                    </span>
                  ),
                },
                {
                  id: "seen",
                  header: t("assetsPage.answer"),
                  cell: (s) => (
                    <span className="as-wrap flex min-w-0 flex-col text-xs">
                      {s.http && (
                        <span>
                          HTTP {s.http.status}
                          {s.http.title ? ` · ${s.http.title}` : ""}
                          {s.http.headers.server ? ` · ${s.http.headers.server}` : ""}
                        </span>
                      )}
                      {s.tls && (
                        <span className="text-fg-muted">
                          {s.tls.protocol} · {s.tls.subject ?? s.tls.sans[0]} · {t("assetsPage.until", { date: day(s.tls.notAfter) })}
                        </span>
                      )}
                      {s.banner && <span className="font-mono text-2xs text-fg-muted">{s.banner}</span>}
                    </span>
                  ),
                },
                {
                  id: "first",
                  header: t("assetsPage.firstSeen"),
                  width: "150px",
                  cell: (s) => <span className="text-xs text-fg-muted">{when(s.firstSeen)}</span>,
                },
              ]}
            />
          </Panel>
          {shown.exposureList.length > 0 && (
            <Panel title={t("assetsPage.exposures")}>
              <ul className="as-list flex flex-col gap-2">
                {shown.exposureList.map((e) => (
                  <li key={e.id} className="flex items-start gap-2 text-sm">
                    <SeverityBadge severity={e.severity} compact />
                    <span className={e.resolvedAt ? "text-fg-muted line-through" : undefined}>
                      {e.title}
                      {e.port ? ` (${e.port})` : ""}
                      <span className="block text-xs text-fg-muted">{e.detail}</span>
                    </span>
                  </li>
                ))}
              </ul>
            </Panel>
          )}
        </div>
      )}
    </Dialog>
  );
}

function AssetsPage({ call, summary }: { call: Call; summary: Summary }) {
  const t = useT();
  const [state, setState] = useState<"present" | "gone">("present");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(param("key"));
  const [data, error] = useLoad<{ assets: Asset[] }>(call, `/api/v1/assets?state=${state}`, 60_000);
  const rows = (data?.assets ?? []).filter((a) => !q || `${a.key} ${a.addresses.join(" ")}`.toLowerCase().includes(q.toLowerCase()));
  const columns: Column<Asset>[] = [
    {
      id: "asset",
      header: t("assetsPage.asset"),
      sortValue: (a) => a.key,
      cell: (a) => (
        <span className="flex min-w-0 flex-col">
          <span className="truncate font-medium">{a.key}</span>
          <span className="truncate font-mono text-2xs text-fg-muted">{a.cname ? `CNAME ${a.cname}` : a.addresses.join(", ")}</span>
        </span>
      ),
    },
    { id: "ports", header: t("assetsPage.ports"), mono: true, cell: (a) => (a.ports.length ? a.ports.join(", ") : <span className="text-fg-muted">–</span>) },
    {
      id: "exposures",
      header: t("assetsPage.exposures"),
      width: "140px",
      sortValue: (a) => (a.worst ? 5 - SEVERITIES.indexOf(a.worst) : 0) * 1000 + a.exposures,
      cell: (a) =>
        a.worst ? (
          <span className="flex items-center gap-1.5">
            <SeverityBadge severity={a.worst} compact />
            <span className="text-xs text-fg-muted">{a.exposures}</span>
          </span>
        ) : (
          <span className="text-fg-muted">–</span>
        ),
    },
    {
      id: "found",
      header: t("assetsPage.foundIn"),
      cell: (a) => (
        <span className="flex flex-wrap gap-1">
          {a.sources.map((s) => (
            <Badge key={s}>{t(`sources.${s}`)}</Badge>
          ))}
        </span>
      ),
    },
    { id: "root", header: t("assetsPage.root"), cell: (a) => <span className="font-mono text-xs">{a.root}</span> },
    {
      id: "first",
      header: state === "gone" ? t("assetsPage.gone") : t("assetsPage.firstSeen"),
      sortValue: (a) => (state === "gone" ? (a.goneAt ?? "") : a.firstSeen),
      cell: (a) => <span className="text-xs whitespace-nowrap text-fg-muted">{when(state === "gone" ? a.goneAt! : a.firstSeen)}</span>,
    },
  ];
  return (
    <>
      <PageHeader
        title={t("assetsPage.assets")}
        description={t("assetsPage.description")}
        actions={
          <SegmentedControl
            label={t("assetsPage.state")}
            value={state}
            onChange={setState}
            options={[
              { value: "present", label: t("assetsPage.present") },
              { value: "gone", label: t("assetsPage.goneTab") },
            ]}
          />
        }
      />
      <NoRoots summary={summary} />
      <KpiGrid minWidth={170}>
        <KpiCard label={t("assetsPage.assets")} value={formatNumber(summary.assets)} icon={Boxes} />
        <KpiCard label={t("assetsPage.openPorts")} value={formatNumber(summary.services)} icon={Network} />
        <KpiCard label={t("changesPage.newAssets")} value={summary.newAssets} unit={t("changesPage.lastWeek")} icon={Plus} />
        <KpiCard label={t("assetsPage.outside")} value={summary.outside} unit={t("assetsPage.notProbedShort")} icon={Globe} href="/domains" />
      </KpiGrid>
      <ErrorText message={error} />
      <Panel
        title={t("assetsPage.assets")}
        description={t("assetsPage.shown", { count: rows.length })}
        actions={<SearchInput label={t("assetsPage.filter")} value={q} onChange={(e) => setQ(e.target.value)} />}
        flush
      >
        <DataTable
          label={t("assetsPage.assets")}
          columns={columns}
          rows={rows}
          loading={!data}
          getRowId={(a) => a.key}
          onRowClick={(a) => setOpen(a.key)}
          activeRowId={open ?? undefined}
          minWidth={980}
          empty={<EmptyState title={t("assetsPage.none")}>{t("assetsPage.noneDetail")}</EmptyState>}
        />
      </Panel>
      <AssetDialog call={call} assetKey={open} onClose={() => setOpen(null)} />
    </>
  );
}

// ---------------------------------------------------------------- Exposures

function ExposuresPage({ call, summary }: { call: Call; summary: Summary }) {
  const t = useT();
  const [state, setState] = useState<"open" | "resolved">("open");
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [data, error] = useLoad<{ exposures: Exposure[] }>(
    call,
    `/api/v1/exposures?state=${state}${severity === "all" ? "" : `&severity=${severity}`}`,
    60_000,
  );
  const columns: Column<Exposure>[] = [
    {
      id: "sev",
      header: t("exposuresPage.severity"),
      width: "110px",
      sortValue: (e) => 5 - SEVERITIES.indexOf(e.severity),
      cell: (e) => <SeverityBadge severity={e.severity} />,
    },
    {
      id: "finding",
      header: t("exposuresPage.finding"),
      width: "40%",
      cell: (e) => (
        <span className="flex min-w-0 flex-col">
          <span className="font-medium">{e.title}</span>
          <span className="as-wrap text-xs text-fg-muted">{e.detail}</span>
        </span>
      ),
    },
    { id: "asset", header: t("exposuresPage.asset"), sortValue: (e) => e.asset, cell: (e) => <Host value={e.asset} /> },
    { id: "port", header: t("exposuresPage.port"), width: "80px", mono: true, align: "right", cell: (e) => e.port ?? "–" },
    {
      id: "first",
      header: state === "open" ? t("exposuresPage.firstSeen") : t("exposuresPage.resolved"),
      align: "right",
      sortValue: (e) => (state === "open" ? e.firstSeen : (e.resolvedAt ?? "")),
      cell: (e) => <span className="text-xs whitespace-nowrap text-fg-muted">{when(state === "open" ? e.firstSeen : e.resolvedAt!)}</span>,
    },
  ];
  const ports = summary.ports.slice(0, 10);
  return (
    <>
      <PageHeader
        title={t("exposuresPage.exposures")}
        description={t("exposuresPage.description")}
        actions={
          <SegmentedControl
            label={t("exposuresPage.state")}
            value={state}
            onChange={setState}
            options={[
              { value: "open", label: t("exposuresPage.open") },
              { value: "resolved", label: t("exposuresPage.resolvedTab") },
            ]}
          />
        }
      />
      <NoRoots summary={summary} />
      <KpiGrid minWidth={140}>
        {SEVERITIES.map((s) => (
          <KpiCard
            key={s}
            label={t(`severities.${s}`)}
            value={summary.exposures[s]}
            tone={!summary.exposures[s] ? undefined : s === "critical" ? "critical" : s === "high" ? "danger" : s === "medium" ? "warning" : undefined}
          />
        ))}
      </KpiGrid>
      <ErrorText message={error} />
      <OverviewGrid>
        <Panel
          title={t("exposuresPage.exposures")}
          description={t("exposuresPage.shown", { count: data?.exposures.length ?? 0 })}
          actions={
            <SegmentedControl
              label={t("exposuresPage.severity")}
              value={severity}
              onChange={setSeverity}
              options={[{ value: "all" as const, label: t("exposuresPage.all") }, ...SEVERITIES.map((s) => ({ value: s, label: t(`severities.${s}`) }))]}
            />
          }
          flush
        >
          <DataTable
            label={t("exposuresPage.exposures")}
            columns={columns}
            rows={data?.exposures ?? []}
            loading={!data}
            getRowId={(e) => e.id}
            onRowClick={(e) => navigate(`/assets?key=${encodeURIComponent(e.asset)}`)}
            minWidth={900}
            empty={<EmptyState title={t("exposuresPage.none")}>{t("exposuresPage.noneDetail")}</EmptyState>}
          />
        </Panel>
        <Panel title={t("exposuresPage.byPort")} description={t("exposuresPage.byPortDetail", { count: summary.assets })}>
          {ports.length ? (
            <BarList
              label={t("exposuresPage.byPort")}
              items={ports.map((p) => ({
                id: String(p.port),
                label: `${p.port} ${p.service}`,
                value: p.count,
                ...(![22, 25, 53, 80, 443, 465, 587, 993, 995, 8443].includes(p.port) && { color: "var(--oa-danger)" }),
              }))}
            />
          ) : (
            <EmptyState title={t("exposuresPage.noPorts")} />
          )}
        </Panel>
      </OverviewGrid>
    </>
  );
}

// ---------------------------------------------------------------- Certificates

const CERT_TONE = { expired: "critical", critical: "danger", expiring: "warning", valid: "success" } as const;

function CertificatesPage({ call, summary }: { call: Call; summary: Summary }) {
  const t = useT();
  const [data, error] = useLoad<{ certificates: Certificate[] }>(call, "/api/v1/certificates", 60_000);
  const columns: Column<Certificate>[] = [
    {
      id: "cn",
      header: t("certificatesPage.subject"),
      width: "26%",
      sortValue: (c) => c.subject ?? "",
      cell: (c) => (
        <span className="flex min-w-0 flex-col">
          <span className="truncate font-mono text-xs">{c.subject ?? c.sans[0] ?? "–"}</span>
          <span className="as-wrap text-2xs text-fg-muted">{c.sans.slice(0, 4).join(", ") + (c.sans.length > 4 ? ` +${c.sans.length - 4}` : "")}</span>
        </span>
      ),
    },
    { id: "issuer", header: t("certificatesPage.issuer"), cell: (c) => <span className="text-xs">{c.issuer ?? "–"}</span> },
    {
      id: "expires",
      header: t("certificatesPage.expires"),
      sortValue: (c) => c.daysLeft,
      cell: (c) => (
        <span className="flex flex-col">
          <StatusBadge tone={CERT_TONE[c.state]}>
            {c.daysLeft < 0 ? t("certificatesPage.expired") : t("certificatesPage.daysLeft", { count: c.daysLeft })}
          </StatusBadge>
          <span className="text-2xs text-fg-muted">{day(c.notAfter)}</span>
        </span>
      ),
    },
    {
      id: "trust",
      header: t("certificatesPage.trust"),
      cell: (c) =>
        c.trusted ? (
          <StatusBadge tone="success">{t("certificatesPage.trusted")}</StatusBadge>
        ) : (
          <span title={c.trustError ?? undefined}>
            <StatusBadge tone="warning">{c.selfSigned ? t("certificatesPage.selfSigned") : t("certificatesPage.untrusted")}</StatusBadge>
          </span>
        ),
    },
    {
      id: "tls",
      header: t("certificatesPage.protocols"),
      cell: (c) => (
        <span className="flex flex-wrap gap-1">
          {c.protocols.map((p) => (
            <Badge key={p} mono>
              {p}
            </Badge>
          ))}
          {c.legacyTls && <Badge tone="warning">{t("certificatesPage.legacy")}</Badge>}
        </span>
      ),
    },
    {
      id: "places",
      header: t("certificatesPage.where"),
      cell: (c) => (
        <span className="as-wrap flex flex-col font-mono text-2xs">
          {c.places.map((p) => (
            <span key={`${p.asset}:${p.port}`} className={p.nameMatches ? undefined : "text-warning-text"}>
              {p.asset}:{p.port}
            </span>
          ))}
        </span>
      ),
    },
  ];
  return (
    <>
      <PageHeader title={t("certificatesPage.certificates")} description={t("certificatesPage.description", { count: summary.settings.certWarnDays })} />
      <KpiGrid minWidth={170}>
        <KpiCard label={t("certificatesPage.certificates")} value={summary.certificates.total} icon={BadgeCheck} />
        <KpiCard label={t("certificatesPage.expiringKpi")} value={summary.certificates.expiring} tone={summary.certificates.expiring ? "warning" : undefined} />
        <KpiCard label={t("certificatesPage.expired")} value={summary.certificates.expired} tone={summary.certificates.expired ? "critical" : undefined} />
      </KpiGrid>
      <ErrorText message={error} />
      <Panel title={t("certificatesPage.certificates")} flush>
        <DataTable
          label={t("certificatesPage.certificates")}
          columns={columns}
          rows={data?.certificates ?? []}
          loading={!data}
          getRowId={(c) => c.fingerprint}
          minWidth={1000}
          empty={<EmptyState title={t("certificatesPage.none")}>{t("certificatesPage.noneDetail")}</EmptyState>}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Domains

const DOMAIN_TONE = { pending: "warning", verified: "success", lost: "danger" } as const;

function Proof({ d }: { d: Domain }) {
  const t = useT();
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-xs text-fg-muted">{t("domainsPage.publish")}</span>
      <Code>{`${d.proof.name}.  3600  IN  TXT  "${d.proof.value}"`}</Code>
    </div>
  );
}

function DomainDialog({ call, open, onClose, onSaved }: { call: Call; open: boolean; onClose: () => void; onSaved: () => void }) {
  const t = useT();
  const [name, setName] = useState("");
  const [added, setAdded] = useState<Domain>();
  const [error, setError] = useState<string>();
  useEffect(() => {
    if (open) (setName(""), setAdded(undefined), setError(undefined));
  }, [open]);
  const save = async (e: FormEvent) => {
    e.preventDefault();
    try {
      setAdded(await call<Domain>("/api/v1/domains", { method: "POST", body: JSON.stringify({ name }) }));
      setError(undefined);
      onSaved();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title={t("domainsPage.add")}
      description={t("domainsPage.addDetail")}
      onSubmit={added ? undefined : (e) => void save(e)}
      footer={
        added ? (
          <Button variant="primary" onClick={onClose}>
            {t("domainsPage.done")}
          </Button>
        ) : (
          <>
            <Button onClick={onClose}>{t("domainsPage.cancel")}</Button>
            <Button type="submit" variant="primary" disabled={!name.trim()}>
              {t("domainsPage.add")}
            </Button>
          </>
        )
      }
    >
      {added ? (
        <div className="flex flex-col gap-2.5">
          <Proof d={added} />
          <p className="m-0 text-xs text-fg-muted">{t("domainsPage.thenVerify")}</p>
        </div>
      ) : (
        <div className="flex flex-col gap-2.5">
          <TextField label={t("domainsPage.name")} value={name} onChange={(e) => setName(e.target.value)} placeholder="example.com" mono />
          <ErrorText message={error} />
        </div>
      )}
    </Dialog>
  );
}

function RangeDialog({ call, open, onClose, onSaved }: { call: Call; open: boolean; onClose: () => void; onSaved: () => void }) {
  const t = useT();
  const [cidr, setCidr] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string>();
  useEffect(() => {
    if (open) (setCidr(""), setReason(""), setError(undefined));
  }, [open]);
  const save = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await call("/api/v1/ranges", { method: "POST", body: JSON.stringify({ cidr, reason }) });
      onSaved();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title={t("domainsPage.addRange")}
      description={t("domainsPage.addRangeDetail")}
      onSubmit={(e) => void save(e)}
      footer={
        <>
          <Button onClick={onClose}>{t("domainsPage.cancel")}</Button>
          <Button type="submit" variant="primary" disabled={!cidr.trim() || reason.trim().length < 10}>
            {t("domainsPage.addRange")}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-2.5">
        <TextField
          label={t("domainsPage.cidr")}
          value={cidr}
          onChange={(e) => setCidr(e.target.value)}
          placeholder="203.0.113.0/28"
          hint={t("domainsPage.cidrHint")}
          mono
        />
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium">{t("domainsPage.reason")}</span>
          <textarea
            className="as-textarea"
            rows={3}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder={t("domainsPage.reasonPlaceholder")}
          />
          <span className="text-xs text-fg-muted">{t("domainsPage.reasonHint")}</span>
        </label>
        <ErrorText message={error} />
      </div>
    </Dialog>
  );
}

function DomainsPage({ call, reloadSummary }: { call: Call; reloadSummary: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [domains, domainsError, reloadDomains] = useLoad<{ domains: Domain[] }>(call, "/api/v1/domains", 30_000);
  const [ranges, , reloadRanges] = useLoad<{ ranges: Range[] }>(call, "/api/v1/ranges");
  const [outside] = useLoad<{ names: Outside[] }>(call, "/api/v1/outside");
  const reload = () => (reloadDomains(), reloadRanges(), reloadSummary());
  const [act, error] = useAct(reload);
  const [adding, setAdding] = useState<"domain" | "range" | null>(null);
  const domainColumns: Column<Domain>[] = [
    {
      id: "name",
      header: t("domainsPage.domain"),
      width: "40%",
      sortValue: (d) => d.name,
      cell: (d) => (
        <span className="flex min-w-0 flex-col gap-1">
          <span className="font-mono font-medium">{d.name}</span>
          {d.state !== "verified" && <Proof d={d} />}
          {d.error && <span className="as-wrap text-2xs text-danger">{d.error}</span>}
        </span>
      ),
    },
    {
      id: "state",
      header: t("domainsPage.state"),
      width: "120px",
      cell: (d) => <StatusBadge tone={DOMAIN_TONE[d.state]}>{t(`domainStates.${d.state}`)}</StatusBadge>,
    },
    {
      id: "records",
      header: t("domainsPage.records"),
      cell: (d) =>
        d.records ? (
          <span className="flex flex-col text-2xs">
            <span>MX {d.records.mx.length ? d.records.mx.join(", ") : "–"}</span>
            <span className={d.records.spf ? undefined : "text-warning-text"}>SPF {d.records.spf ? "✓" : "–"}</span>
            <span className={d.records.dmarc ? undefined : "text-warning-text"}>DMARC {d.records.dmarc ?? "–"}</span>
          </span>
        ) : (
          <span className="text-fg-muted">–</span>
        ),
    },
    { id: "assets", header: t("domainsPage.assets"), align: "right", mono: true, cell: (d) => d.assets },
    { id: "checked", header: t("domainsPage.checked"), cell: (d) => <span className="text-xs text-fg-muted">{d.checkedAt ? when(d.checkedAt) : "–"}</span> },
    {
      id: "actions",
      header: <span className="sr-only">{t("domainsPage.actions")}</span>,
      label: t("domainsPage.actions"),
      width: "150px",
      align: "right",
      hideable: false,
      cell: (d) => (
        <span className="flex justify-end gap-1.5">
          {can("editor") && d.state !== "verified" && (
            <Button size="xs" icon={<ShieldCheck />} onClick={() => void act(() => call(`/api/v1/domains/${d.id}/verify`, { method: "POST" }))}>
              {t("domainsPage.verify")}
            </Button>
          )}
          {can("admin") && (
            <IconButton
              size="xs"
              variant="danger"
              label={t("domainsPage.delete", { name: d.name })}
              onClick={() =>
                window.confirm(t("domainsPage.confirmDelete", { name: d.name })) && void act(() => call(`/api/v1/domains/${d.id}`, { method: "DELETE" }))
              }
            >
              <Trash2 />
            </IconButton>
          )}
        </span>
      ),
    },
  ];
  const rangeColumns: Column<Range>[] = [
    { id: "cidr", header: t("domainsPage.cidr"), mono: true, cell: (r) => r.cidr },
    { id: "addresses", header: t("domainsPage.addresses"), align: "right", mono: true, cell: (r) => r.addresses },
    { id: "reason", header: t("domainsPage.reason"), width: "40%", cell: (r) => <span className="as-wrap text-xs">{r.reason}</span> },
    {
      id: "by",
      header: t("domainsPage.addedBy"),
      cell: (r) => <span className="text-xs">{t("domainsPage.byOn", { name: r.createdBy, when: day(r.createdAt) })}</span>,
    },
    {
      id: "actions",
      header: <span className="sr-only">{t("domainsPage.actions")}</span>,
      label: t("domainsPage.actions"),
      width: "60px",
      align: "right",
      hideable: false,
      cell: (r) =>
        can("admin") && (
          <IconButton
            size="xs"
            variant="danger"
            label={t("domainsPage.delete", { name: r.cidr })}
            onClick={() =>
              window.confirm(t("domainsPage.confirmDelete", { name: r.cidr })) && void act(() => call(`/api/v1/ranges/${r.id}`, { method: "DELETE" }))
            }
          >
            <Trash2 />
          </IconButton>
        ),
    },
  ];
  const outsideColumns: Column<Outside>[] = [
    { id: "name", header: t("domainsPage.name"), sortValue: (o) => o.name, cell: (o) => <span className="font-mono text-xs">{o.name}</span> },
    { id: "seen", header: t("domainsPage.seenAs"), cell: (o) => <Badge>{t(`seenAs.${o.seenAs}`)}</Badge> },
    { id: "via", header: t("domainsPage.via"), cell: (o) => <span className="font-mono text-xs text-fg-muted">{o.via}</span> },
    { id: "last", header: t("domainsPage.lastSeen"), cell: (o) => <span className="text-xs text-fg-muted">{when(o.lastSeen)}</span> },
  ];
  return (
    <>
      <PageHeader
        title={t("domainsPage.domains")}
        description={t("domainsPage.description")}
        actions={
          <>
            {can("admin") && (
              <Button icon={<Network />} onClick={() => setAdding("range")}>
                {t("domainsPage.addRange")}
              </Button>
            )}
            {can("editor") && (
              <Button variant="primary" icon={<Plus />} onClick={() => setAdding("domain")}>
                {t("domainsPage.add")}
              </Button>
            )}
          </>
        }
      />
      <ErrorText message={error ?? domainsError} />
      <Panel title={t("domainsPage.domains")} description={t("domainsPage.domainsDetail")} flush>
        <DataTable
          label={t("domainsPage.domains")}
          columns={domainColumns}
          rows={domains?.domains ?? []}
          loading={!domains}
          getRowId={(d) => d.id}
          minWidth={1000}
          empty={<EmptyState title={t("domainsPage.none")}>{t("domainsPage.noneDetail")}</EmptyState>}
        />
      </Panel>
      <Panel title={t("domainsPage.ranges")} description={t("domainsPage.rangesDetail")} flush>
        <DataTable
          label={t("domainsPage.ranges")}
          columns={rangeColumns}
          rows={ranges?.ranges ?? []}
          loading={!ranges}
          getRowId={(r) => r.id}
          minWidth={800}
          empty={<EmptyState title={t("domainsPage.noRanges")} />}
        />
      </Panel>
      <Panel title={t("domainsPage.outside")} description={t("domainsPage.outsideDetail")} flush>
        <DataTable
          label={t("domainsPage.outside")}
          columns={outsideColumns}
          rows={outside?.names ?? []}
          loading={!outside}
          getRowId={(o) => o.name}
          minWidth={700}
          empty={<EmptyState title={t("domainsPage.noOutside")} />}
        />
      </Panel>
      <DomainDialog call={call} open={adding === "domain"} onClose={() => setAdding(null)} onSaved={reload} />
      <RangeDialog call={call} open={adding === "range"} onClose={() => setAdding(null)} onSaved={() => (setAdding(null), reload())} />
    </>
  );
}

// ---------------------------------------------------------------- Scans

const SCAN_TONE = { running: "info", done: "success", failed: "danger" } as const;

function ScansPage({ call, summary, reloadSummary }: { call: Call; summary: Summary; reloadSummary: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [data, loadError, reload] = useLoad<{ scans: Scan[] }>(call, "/api/v1/scans", summary.scanning ? 3000 : 15_000);
  const [act, error] = useAct(() => (reload(), reloadSummary()));
  const last = data?.scans[0];
  const s = summary.settings;
  const columns: Column<Scan>[] = [
    {
      id: "started",
      header: t("scansPage.started"),
      sortValue: (r) => r.startedAt,
      cell: (r) => <span className="text-xs whitespace-nowrap">{when(r.startedAt)}</span>,
    },
    {
      id: "trigger",
      header: t("scansPage.trigger"),
      cell: (r) => <Badge>{r.trigger === "schedule" ? t("scansPage.schedule") : t("scansPage.by", { name: r.startedBy ?? "" })}</Badge>,
    },
    { id: "roots", header: t("scansPage.roots"), cell: (r) => <span className="as-wrap font-mono text-2xs">{r.roots.join(", ") || "–"}</span> },
    { id: "duration", header: t("scansPage.duration"), align: "right", mono: true, cell: duration },
    { id: "assets", header: t("scansPage.assets"), align: "right", mono: true, cell: (r) => r.assets },
    { id: "services", header: t("scansPage.services"), align: "right", mono: true, cell: (r) => r.services },
    { id: "exposures", header: t("scansPage.exposures"), align: "right", mono: true, cell: (r) => r.exposures },
    {
      id: "changes",
      header: t("scansPage.changes"),
      align: "right",
      mono: true,
      cell: (r) => (r.changes ? <a href={`/changes?scan=${r.id}`}>{r.changes}</a> : 0),
    },
    { id: "probes", header: t("scansPage.probes"), align: "right", mono: true, cell: (r) => formatNumber(r.probes) },
    {
      id: "state",
      header: t("scansPage.state"),
      width: "110px",
      cell: (r) => <StatusBadge tone={SCAN_TONE[r.state]}>{t(`scanStates.${r.state}`)}</StatusBadge>,
    },
  ];
  return (
    <>
      <PageHeader
        title={t("scansPage.scans")}
        description={t("scansPage.description")}
        actions={
          can("editor") && (
            <Button variant="primary" icon={<Play />} loading={summary.scanning} onClick={() => void act(() => call("/api/v1/scans", { method: "POST" }))}>
              {summary.scanning ? t("scansPage.running") : t("scansPage.scanNow")}
            </Button>
          )
        }
      />
      <ErrorText message={error ?? loadError} />
      {last?.state === "failed" && (
        <Callout tone="danger" title={t("scansPage.failed")}>
          {last.error}
        </Callout>
      )}
      {last && last.warnings.length > 0 && (
        <Callout tone="warning" title={t("scansPage.warnings")}>
          {last.warnings.join(" ")}
        </Callout>
      )}
      <OverviewGrid>
        <Panel title={t("scansPage.history")} flush>
          <DataTable
            label={t("scansPage.history")}
            columns={columns}
            rows={data?.scans ?? []}
            loading={!data}
            getRowId={(r) => r.id}
            minWidth={1100}
            empty={<EmptyState title={t("scansPage.none")} />}
          />
        </Panel>
        <Panel title={t("scansPage.settings")} description={t("scansPage.settingsDetail")}>
          <dl className="as-facts text-sm">
            <dt className="text-fg-muted">{t("scansPage.every")}</dt>
            <dd>{t("scansPage.hours", { count: s.scanHours })}</dd>
            <dt className="text-fg-muted">{t("scansPage.next")}</dt>
            <dd>{summary.domains.verified || summary.ranges ? when(summary.nextScanAt) : t("scansPage.nothing")}</dd>
            <dt className="text-fg-muted">{t("scansPage.rate")}</dt>
            <dd>{s.ratePerSecond === null ? "–" : t("scansPage.perSecond", { count: s.ratePerSecond })}</dd>
            <dt className="text-fg-muted">{t("scansPage.ports")}</dt>
            <dd className="font-mono text-xs">{s.ports.join(", ")}</dd>
            <dt className="text-fg-muted">{t("scansPage.ct")}</dt>
            <dd>{s.certificateTransparency ? t("scansPage.on") : t("scansPage.off")}</dd>
            <dt className="text-fg-muted">{t("scansPage.private")}</dt>
            <dd>{s.allowPrivate ? t("scansPage.allowed") : t("scansPage.refused")}</dd>
          </dl>
          <p className="mt-3 mb-0 text-xs text-fg-muted">{t("scansPage.never")}</p>
        </Panel>
      </OverviewGrid>
    </>
  );
}

// ---------------------------------------------------------------- Audit

function AuditPage({ call }: { call: Call }) {
  const t = useT();
  const { can } = useAuth();
  const [data, error] = useLoad<{ entries: AuditEntry[] }>(call, can("admin") ? "/api/v1/audit" : null);
  if (!can("admin")) return <EmptyState title={t("settingsPage.adminsOnly")}>{t("settingsPage.askAnAdmin")}</EmptyState>;
  const columns: Column<AuditEntry>[] = [
    { id: "at", header: t("auditPage.when"), width: "170px", cell: (e) => <span className="text-xs whitespace-nowrap">{when(e.at)}</span> },
    { id: "actor", header: t("auditPage.who"), cell: (e) => <span className="text-xs">{e.actor}</span> },
    { id: "action", header: t("auditPage.action"), cell: (e) => <Badge mono>{e.action}</Badge> },
    { id: "target", header: t("auditPage.target"), cell: (e) => <span className="font-mono text-xs">{e.target}</span> },
    { id: "detail", header: t("auditPage.detail"), width: "36%", cell: (e) => <span className="as-wrap text-xs text-fg-muted">{e.detail || "–"}</span> },
  ];
  return (
    <>
      <PageHeader title={t("auditPage.audit")} description={t("auditPage.description")} />
      <ErrorText message={error} />
      <Panel title={t("auditPage.audit")} flush>
        <DataTable
          label={t("auditPage.audit")}
          columns={columns}
          rows={data?.entries ?? []}
          loading={!data}
          getRowId={(e) => String(e.id)}
          minWidth={900}
          empty={<EmptyState title={t("auditPage.none")} />}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const t = useT();
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title={t("settingsPage.adminsOnly")}>{t("settingsPage.askAnAdmin")}</EmptyState>;
  return (
    <>
      <PageHeader
        title={t(`settingsPage.${page}.title`)}
        description={t(`settingsPage.${page}.description`)}
        actions={
          page === "account" && (
            <Button icon={<LogOut />} onClick={() => void signOut()}>
              {t("settingsPage.signOut")}
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function pageOf(msg: T, page: Page, call: Call, summary: Summary, reloadSummary: () => void) {
  if (page === "changes") return <ChangesPage call={call} summary={summary} reloadSummary={reloadSummary} />;
  if (page === "assets") return <AssetsPage call={call} summary={summary} />;
  if (page === "exposures") return <ExposuresPage call={call} summary={summary} />;
  if (page === "certificates") return <CertificatesPage call={call} summary={summary} />;
  if (page === "domains") return <DomainsPage call={call} reloadSummary={reloadSummary} />;
  if (page === "scans") return <ScansPage call={call} summary={summary} reloadSummary={reloadSummary} />;
  if (page === "audit") return <AuditPage call={call} />;
  return <EmptyState title={msg("product.loading")} />;
}

function Product() {
  const msg = useT();
  const [theme, setTheme] = useThemePreference();
  const [, setLocale] = useLocalePreference();
  const { me, can } = useAuth();
  const account = useAccountMenu();
  const page = parsePage(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();
  const onSearch = useMemo(() => search(call, msg), [call, msg]);

  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) =>
        setProducts(
          r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "attack-surface" && (PRODUCT_IDS as readonly string[]).includes(p.id)),
        ),
      () => {},
    );
  }, [call]);

  const reloadSummary = useCallback(() => void call<Summary>("/api/v1/summary").then(setSummary, () => {}), [call]);
  useEffect(() => {
    reloadSummary();
    const t = setInterval(reloadSummary, summary?.scanning ? 3000 : 15_000);
    return () => clearInterval(t);
  }, [reloadSummary, summary?.scanning]);

  const nav = [
    { id: "changes", label: msg("product.changes"), icon: GitCompare, count: summary?.unacknowledged || undefined },
    { id: "assets", label: msg("product.assets"), icon: Boxes, count: summary?.assets || undefined },
    { id: "exposures", label: msg("product.exposures"), icon: TriangleAlert, count: summary?.exposures.total || undefined },
    { id: "certificates", label: msg("product.certificates"), icon: BadgeCheck },
    { id: "domains", label: msg("product.domains"), icon: Globe, count: summary ? summary.domains.pending + summary.domains.lost || undefined : undefined },
    { id: "scans", label: msg("product.scans"), icon: Radar },
  ];
  const footerNav = [
    ...(can("admin")
      ? [
          { id: "audit", label: msg("product.audit"), icon: ScrollText },
          { id: "members", label: msg("product.members"), icon: Users },
          { id: "signin", label: msg("product.signIn"), icon: LogIn },
          { id: "tokens", label: msg("product.apiTokens"), icon: KeyRound },
        ]
      : []),
    { id: "account", label: msg("product.account"), icon: UserRound },
  ];
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);
  const settings = page === "account" || page === "members" || page === "signin" || page === "tokens";

  return (
    <AppShell
      product="attack-surface"
      onSearch={onSearch}
      about={colophon}
      nav={nav}
      activeNav={page}
      onNavigate={(id) => navigate(`/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={account.settings(footerNav)}
      user={{ name: me.user.name, role: roleName, ...account.user }}
      theme={theme}
      onThemeChange={setTheme}
      onLanguageChange={(code) => setLocale(toLocale(code))}
    >
      {settings ? (
        <SettingsPage page={page as "account" | "members" | "signin" | "tokens"} />
      ) : !summary ? (
        <EmptyState title={msg("product.loading")} icon={<RefreshCw />}>
          {msg("product.reading")}
        </EmptyState>
      ) : (
        pageOf(msg, page, call, summary, reloadSummary)
      )}
    </AppShell>
  );
}

export function App() {
  const installBrand = useInstallBrand();
  const [theme] = useThemePreference();
  const [locale] = useLocalePreference();
  return (
    // The install's brand from config/brand.env (ADR 0053); OpenAsy's own look where it sets none.
    <BrandProvider theme={theme} locale={locale} brand={{ name: "OpenAsy", organization: undefined, ...installBrand }} className="min-h-screen">
      <AuthGate product="OpenAsy Attack Surface">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
