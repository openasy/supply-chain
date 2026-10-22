// Prometheus text exposition, written by hand: a few lines, no client library needed.
const requests = new Map<string, number>();

export function countRequest(method: string, route: string, status: number) {
  const key = `method="${method}",route="${route}",status="${status}"`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
}

export interface Gauges {
  images: number;
  allowed: number;
  denied: number;
  allowedByException: number;
  withoutSbom: number;
  activeExceptions: number;
  packages: number;
}

export function renderMetrics(version: string, g: Gauges): string {
  const gauge = (name: string, help: string, value: number) => [`# HELP ${name} ${help}`, `# TYPE ${name} gauge`, `${name} ${value}`];
  const lines = [
    "# HELP openasy_build_info Build information.",
    "# TYPE openasy_build_info gauge",
    `openasy_build_info{product="supply-chain",version="${version}"} 1`,
    "# HELP openasy_http_requests_total HTTP requests handled.",
    "# TYPE openasy_http_requests_total counter",
    ...[...requests].map(([labels, n]) => `openasy_http_requests_total{${labels}} ${n}`),
    ...gauge("openasy_supply_chain_images", "Images with evidence.", g.images),
    ...gauge("openasy_supply_chain_images_allowed", "Images the policy allows, with or without an exception.", g.allowed),
    ...gauge("openasy_supply_chain_images_denied", "Images the policy denies.", g.denied),
    ...gauge("openasy_supply_chain_images_allowed_by_exception", "Images that are allowed only because of an exception.", g.allowedByException),
    ...gauge("openasy_supply_chain_images_without_sbom", "Images with no SBOM.", g.withoutSbom),
    ...gauge("openasy_supply_chain_active_exceptions", "Exceptions that have not ended.", g.activeExceptions),
    ...gauge("openasy_supply_chain_packages", "Packages in every stored SBOM.", g.packages),
    "# HELP process_uptime_seconds Seconds since the process started.",
    "# TYPE process_uptime_seconds gauge",
    `process_uptime_seconds ${process.uptime().toFixed(0)}`,
  ];
  return lines.join("\n") + "\n";
}
