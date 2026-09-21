import type { DnsUpstream, TransportKind } from "./types";

export function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(
    Math.floor(Math.log(value) / Math.log(1024)),
    units.length - 1,
  );
  const amount = value / 1024 ** index;
  return `${amount >= 10 || index === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[index]}`;
}

export function validateHost(value: string): boolean {
  const host = value.trim();
  if (host.includes(":")) {
    if (!/^[0-9a-f:.]+$/i.test(host)) return false;
    try {
      // Parse an IPv6 literal locally; constructing URL performs no request.
      const address = new URL(`http://[${host}]`).hostname;
      return address !== "[::]" && !address.toLowerCase().startsWith("[ff");
    } catch { return false; }
  }
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    return host.split(".").every((part) => Number(part) <= 255);
  }
  return (
    host.length > 0 &&
    host.length <= 253 &&
    host
      .split(".")
      .every(
        (label) =>
          label.length > 0 &&
          label.length <= 63 &&
          !label.startsWith("-") &&
          !label.endsWith("-") &&
          /^[a-z0-9-]+$/i.test(label),
      )
  );
}

export function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  if (days > 0) return `${days}d ${hours}h`;
  const minutes = Math.floor((seconds % 3_600) / 60);
  return `${hours}h ${minutes}m`;
}

// The interface is English; numeric grouping must not follow the host's locale.
const countFormatter = new Intl.NumberFormat("en-US", {
  maximumFractionDigits: 0,
});
export function formatCount(value: number | undefined): string {
  return value === undefined || !Number.isFinite(value) || value < 0
    ? "Unavailable"
    : countFormatter.format(value);
}

export function formatTunnelDuration(seconds: number | undefined): string {
  if (seconds === undefined || !Number.isFinite(seconds) || seconds < 0)
    return "Unavailable";
  const whole = Math.floor(seconds);
  const pad = (value: number) => String(value).padStart(2, "0");
  if (whole < 3600) return `${pad(Math.floor(whole / 60))}:${pad(whole % 60)}`;
  return `${Math.floor(whole / 3600)}:${pad(Math.floor(whole / 60) % 60)}:${pad(whole % 60)}`;
}

export function formatRate(bytesPerSecond: number | undefined): string {
  if (
    bytesPerSecond === undefined ||
    !Number.isFinite(bytesPerSecond) ||
    bytesPerSecond < 0
  ) {
    return "Unavailable";
  }
  return `${formatBytes(bytesPerSecond)}/s`;
}

export function formatCpuUsage(basisPoints: number | undefined): string {
  if (
    basisPoints === undefined ||
    !Number.isFinite(basisPoints) ||
    basisPoints < 0
  ) {
    return "Unavailable";
  }
  return `${(Math.min(basisPoints, 10_000) / 100).toFixed(1)}%`;
}

export function formatMemoryUsage(
  usedBytes: number | undefined,
  totalBytes: number | undefined,
): string {
  if (
    usedBytes === undefined ||
    totalBytes === undefined ||
    !Number.isFinite(usedBytes) ||
    !Number.isFinite(totalBytes) ||
    usedBytes < 0 ||
    totalBytes <= 0
  ) {
    return "Unavailable";
  }
  const percentage = Math.min(100, (usedBytes / totalBytes) * 100);
  return `${percentage.toFixed(0)}% · ${formatBytes(usedBytes)}`;
}

export function formatLatency(milliseconds: number | undefined): string {
  if (
    milliseconds === undefined ||
    !Number.isFinite(milliseconds) ||
    milliseconds < 0
  ) {
    return "Unavailable";
  }
  return milliseconds < 1 ? "<1 ms" : `${Math.round(milliseconds)} ms`;
}

export function formatTransport(transport: TransportKind | undefined): string {
  if (transport === "direct_udp") return "Direct UDP";
  if (transport === "obfuscated_udp") return "Obfuscated UDP";
  if (transport === "tls_like") return "TLS fallback";
  if (transport === "tcp_fallback") return "TCP fallback";
  return "Unavailable";
}

export function formatDnsStatus(
  upstream: DnsUpstream | undefined,
  healthy: boolean | undefined,
  connected: boolean,
): string {
  if (!connected) return "Inactive";
  if (healthy === undefined) return "Checking";
  if (!healthy) return "Unavailable";
  if (upstream?.mode === "split") return "Split DNS active";
  if (upstream?.mode === "dns_over_tls") return "DoT active";
  if (upstream?.mode === "dns_over_https") return "DoH active";
  return "Recursive";
}

export function formatDnsPolicy(upstream: DnsUpstream): string {
  if (upstream.mode === "split") return `Split DNS · ${upstream.zones.length} zones · ${formatDnsPolicy(upstream.default)}`;
  if (upstream.mode === "recursive") return "Recursive DNS";
  const protocol =
    upstream.mode === "dns_over_tls" ? "DNS over TLS" : "DNS over HTTPS";
  return `${protocol} · ${upstream.endpoints.length} endpoint${upstream.endpoints.length === 1 ? "" : "s"}`;
}
