import type { DnsUpstream, TransportKind } from "./types";
import { formatNumber, t } from "./i18n";

export function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let index = Math.max(
    0,
    Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1),
  );
  // Values that round up to 1024 read as the next unit, not "1024 KB".
  if (index < units.length - 1 && Math.round(value / 1024 ** index) >= 1024) index += 1;
  const amount = value / 1024 ** index;
  const digits = amount >= 10 || index === 0 ? 0 : 1;
  const unit = units[index] as "B" | "KB" | "MB" | "GB" | "TB";
  return t(`format.bytes.${unit}`, { value: formatNumber(amount, { minimumFractionDigits: digits, maximumFractionDigits: digits }) });
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
  if (days > 0) return t("format.uptimeDays", { days, hours });
  const minutes = Math.floor((seconds % 3_600) / 60);
  return t("format.uptimeHours", { hours, minutes });
}

// Numbers follow the interface locale, not the host's, so they match the surrounding text.
export function formatCount(value: number | undefined): string {
  return value === undefined || !Number.isFinite(value) || value < 0
    ? t("format.unavailable")
    : formatNumber(value, { maximumFractionDigits: 0 });
}

export function formatTunnelDuration(seconds: number | undefined): string {
  if (seconds === undefined || !Number.isFinite(seconds) || seconds < 0)
    return t("format.unavailable");
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
    return t("format.unavailable");
  }
  return t("format.rate", { value: formatBytes(bytesPerSecond) });
}

export function formatCpuUsage(basisPoints: number | undefined): string {
  if (
    basisPoints === undefined ||
    !Number.isFinite(basisPoints) ||
    basisPoints < 0
  ) {
    return t("format.unavailable");
  }
  return formatNumber(Math.min(basisPoints, 10_000) / 10_000, { style: "percent", minimumFractionDigits: 1, maximumFractionDigits: 1 });
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
    return t("format.unavailable");
  }
  const share = Math.min(1, usedBytes / totalBytes);
  return t("format.memoryUsage", { percent: formatNumber(share, { style: "percent", maximumFractionDigits: 0 }), used: formatBytes(usedBytes) });
}

export function formatLatency(milliseconds: number | undefined): string {
  if (
    milliseconds === undefined ||
    !Number.isFinite(milliseconds) ||
    milliseconds < 0
  ) {
    return t("format.unavailable");
  }
  return milliseconds < 1 ? t("format.latencyBelowOne") : t("format.latency", { value: formatNumber(Math.round(milliseconds)) });
}

export function formatTransport(transport: TransportKind | undefined): string {
  return transport ? t(`format.transport.${transport}`) : t("format.unavailable");
}

export function formatDnsPolicy(upstream: DnsUpstream): string {
  if (upstream.mode === "split") return t("format.dnsPolicy.split", { count: upstream.zones.length, fallback: formatDnsPolicy(upstream.default) });
  if (upstream.mode === "recursive") return t("format.dnsPolicy.recursive");
  const count = upstream.endpoints.length;
  return upstream.mode === "dns_over_tls" ? t("format.dnsPolicy.dnsOverTls", { count }) : t("format.dnsPolicy.dnsOverHttps", { count });
}
