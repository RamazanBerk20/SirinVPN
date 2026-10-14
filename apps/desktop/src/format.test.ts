import { describe, expect, it } from "vitest";
import {
  formatBytes,
  formatCpuUsage,
  formatDnsPolicy,
  formatLatency,
  formatMemoryUsage,
  formatRate,
  formatTransport,
  formatUptime,
  validateHost,
} from "./format";

describe("desktop formatting", () => {
  it("formats live byte counters without fake precision", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(12 * 1024 * 1024)).toBe("12 MB");
    expect(formatBytes(0.3)).toBe("0 B");
    expect(formatBytes(1024 * 1024 - 1)).toBe("1.0 MB");
  });

  it("rejects command-shaped hosts", () => {
    expect(validateHost("vpn.example.org")).toBe(true);
    expect(validateHost("203.0.113.4")).toBe(true);
    expect(validateHost("vpn.example.org; reboot")).toBe(false);
    expect(validateHost("vpn.example.org;reboot")).toBe(false);
    expect(validateHost("999.0.0.1")).toBe(false);
  });

  it("formats current uptime", () => {
    expect(formatUptime(90_000)).toBe("1d 1h");
  });

  it("labels only implemented transports", () => {
    expect(formatTransport("direct_udp")).toBe("Direct UDP");
    expect(formatTransport("obfuscated_udp")).toBe("Obfuscated UDP");
    expect(formatTransport("tls_like")).toBe("TLS fallback");
    expect(formatTransport("tcp_fallback")).toBe("TCP fallback");
    expect(formatTransport(undefined)).toBe("Unavailable");
  });

  it("formats ephemeral server samples without inventing missing values", () => {
    expect(formatRate(1536)).toBe("1.5 KB/s");
    expect(formatRate(undefined)).toBe("Unavailable");
    expect(formatCpuUsage(3750)).toBe("37.5%");
    expect(formatCpuUsage(undefined)).toBe("Unavailable");
    expect(formatMemoryUsage(512 * 1024 * 1024, 2 * 1024 * 1024 * 1024)).toBe("25% · 512 MB");
    expect(formatMemoryUsage(undefined, undefined)).toBe("Unavailable");
    expect(formatLatency(0.4)).toBe("<1 ms");
    expect(formatLatency(18.6)).toBe("19 ms");
  });

  it("describes the configured DNS policy", () => {
    expect(formatDnsPolicy({
      mode: "dns_over_tls",
      endpoints: [{ address: "1.1.1.1", authentication_name: "one.one.one.one" }],
    })).toBe("DNS over TLS · 1 server");
    expect(formatDnsPolicy({
      mode: "dns_over_https",
      endpoints: [{
        address: "1.1.1.1",
        authentication_name: "cloudflare-dns.com",
        path: "/dns-query",
      }],
    })).toBe("DNS over HTTPS · 1 server");
  });
});
