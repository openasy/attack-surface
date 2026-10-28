// Prometheus text exposition, written by hand: a few lines, no client library needed. What is exposed now and the
// last scan are here too, so Metrics can keep them and Alerts can fire on a new critical exposure (ADR 0067).
import type { Surface } from "./surface.ts";

const requests = new Map<string, number>();

export function countRequest(method: string, route: string, status: number) {
  const key = `method="${method}",route="${route}",status="${status}"`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
}

export function renderMetrics(version: string, s: ReturnType<Surface["summary"]>): string {
  const last = s.lastScan;
  const lines = [
    "# HELP openasy_build_info Build information.",
    "# TYPE openasy_build_info gauge",
    `openasy_build_info{product="attack-surface",version="${version}"} 1`,
    "# HELP openasy_http_requests_total HTTP requests handled.",
    "# TYPE openasy_http_requests_total counter",
    ...[...requests].map(([labels, n]) => `openasy_http_requests_total{${labels}} ${n}`),
    "# HELP openasy_attack_surface_domains Domains added, by whether their ownership is proven.",
    "# TYPE openasy_attack_surface_domains gauge",
    ...(["verified", "pending", "lost"] as const).map((state) => `openasy_attack_surface_domains{state="${state}"} ${s.domains[state]}`),
    "# HELP openasy_attack_surface_ranges Address ranges an admin added.",
    "# TYPE openasy_attack_surface_ranges gauge",
    `openasy_attack_surface_ranges ${s.ranges}`,
    "# HELP openasy_attack_surface_assets Host names and addresses that answer.",
    "# TYPE openasy_attack_surface_assets gauge",
    `openasy_attack_surface_assets ${s.assets}`,
    "# HELP openasy_attack_surface_services Open ports across every asset.",
    "# TYPE openasy_attack_surface_services gauge",
    `openasy_attack_surface_services ${s.services}`,
    "# HELP openasy_attack_surface_exposures Open exposures, by severity.",
    "# TYPE openasy_attack_surface_exposures gauge",
    ...(["critical", "high", "medium", "low", "info"] as const).map((sev) => `openasy_attack_surface_exposures{severity="${sev}"} ${s.exposures[sev]}`),
    "# HELP openasy_attack_surface_certificates_expiring Certificates presented that end within the warning days, or have ended.",
    "# TYPE openasy_attack_surface_certificates_expiring gauge",
    `openasy_attack_surface_certificates_expiring ${s.certificates.expiring + s.certificates.expired}`,
    "# HELP openasy_attack_surface_changes_unacknowledged Changes nobody has acknowledged yet.",
    "# TYPE openasy_attack_surface_changes_unacknowledged gauge",
    `openasy_attack_surface_changes_unacknowledged ${s.unacknowledged}`,
    "# HELP openasy_attack_surface_last_scan_timestamp_seconds When the last scan finished.",
    "# TYPE openasy_attack_surface_last_scan_timestamp_seconds gauge",
    ...(last?.finishedAt ? [`openasy_attack_surface_last_scan_timestamp_seconds ${Math.round(Date.parse(last.finishedAt) / 1000)}`] : []),
    "# HELP openasy_attack_surface_last_scan_success 1 when the last scan finished, 0 when it failed.",
    "# TYPE openasy_attack_surface_last_scan_success gauge",
    ...(last && last.state !== "running" ? [`openasy_attack_surface_last_scan_success ${last.state === "done" ? 1 : 0}`] : []),
    "# HELP process_uptime_seconds Seconds since the process started.",
    "# TYPE process_uptime_seconds gauge",
    `process_uptime_seconds ${process.uptime().toFixed(0)}`,
  ];
  return lines.join("\n") + "\n";
}
