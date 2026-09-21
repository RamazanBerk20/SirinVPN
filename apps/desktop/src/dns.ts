import type { PrivateDnsRecord } from "./types";

function parseIpv4(value: string): number[] | null {
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return null;
  const octets = value.split(".").map(Number);
  return octets.every((part) => part <= 255) ? octets : null;
}

function parseIpv6(value: string): number[] | null {
  let address = value.toLowerCase();
  if (!address.includes(":") || address.includes("%")) return null;

  const ipv4Tail = address.slice(address.lastIndexOf(":") + 1);
  if (ipv4Tail.includes(".")) {
    const octets = parseIpv4(ipv4Tail);
    if (!octets) return null;
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    address = `${address.slice(0, address.lastIndexOf(":") + 1)}${high}:${low}`;
  }
  if (address.includes(".")) return null;

  const halves = address.split("::");
  if (halves.length > 2) return null;
  const parseHalf = (half: string): number[] | null => {
    if (!half) return [];
    const parts = half.split(":");
    if (!parts.every((part) => /^[0-9a-f]{1,4}$/.test(part))) return null;
    return parts.map((part) => Number.parseInt(part, 16));
  };
  const left = parseHalf(halves[0]);
  const right = parseHalf(halves[1] ?? "");
  if (!left || !right) return null;
  const present = left.length + right.length;
  if (halves.length === 1) return present === 8 ? left : null;
  if (present >= 8) return null;
  return [...left, ...Array.from({ length: 8 - present }, () => 0), ...right];
}

export function privateDnsRecordsFromDraft(value: string): PrivateDnsRecord[] {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const separator = line.indexOf("=");
      const rawName = line.slice(0, separator).trim().replace(/\.$/, "");
      return {
        name: rawName.toLowerCase(),
        address: line.slice(separator + 1).trim(),
      };
    });
}

export function dnsEndpointAddressIsUsable(value: string): boolean {
  const address = value.trim().toLowerCase();
  if (address.includes(":")) {
    const groups = parseIpv6(address);
    if (!groups) return false;
    const unspecified = groups.every((group) => group === 0);
    const loopback = groups.slice(0, 7).every((group) => group === 0) && groups[7] === 1;
    const linkLocal = (groups[0] & 0xffc0) === 0xfe80;
    const multicast = (groups[0] & 0xff00) === 0xff00;
    return !unspecified && !loopback && !linkLocal && !multicast;
  }
  const octets = parseIpv4(address);
  if (!octets) return false;
  return octets[0] !== 0
    && octets[0] !== 127
    && !(octets[0] === 169 && octets[1] === 254)
    && octets[0] < 224
    && address !== "255.255.255.255";
}

export function dnsOverHttpsPathIsValid(value: string): boolean {
  const path = value.trim();
  if (path.length === 0 || path.length > 255 || !path.startsWith("/") || /[^\x00-\x7f]/.test(path)) {
    return false;
  }
  for (let index = 0; index < path.length;) {
    const character = path[index];
    if (/[a-z0-9/\-_.~]/i.test(character)) {
      index += 1;
    } else if (character === "%" && /^[0-9a-f]{2}$/i.test(path.slice(index + 1, index + 3))) {
      index += 3;
    } else {
      return false;
    }
  }
  return true;
}

export function privateDnsNameIsValid(value: string): boolean {
  const name = value.trim().replace(/\.$/, "").toLowerCase();
  const labels = name.split(".");
  return name.length > 0
    && name.length <= 253
    && labels.length >= 2
    && name !== "localhost"
    && !name.endsWith(".localhost")
    && labels.every((label) => (
      label.length > 0
      && label.length <= 63
      && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
    ));
}

export function privateResolverAddressIsUsable(value: string): boolean {
  const address = value.trim().toLowerCase();
  const v6 = parseIpv6(address);
  if (v6) return (v6[0] & 0xfe00) === 0xfc00;
  const v4 = parseIpv4(address);
  if (!v4 || address === "10.77.0.1" || (v4[0] === 10 && v4[1] === 77 && v4[2] === 0 && v4[3] >= 224)) return false;
  return v4[0] === 10 || (v4[0] === 172 && v4[1] >= 16 && v4[1] <= 31) || (v4[0] === 192 && v4[1] === 168);
}

export function privateDnsDraftIsValid(value: string, emptyAllowed: boolean): boolean {
  const lines = value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.length === 0) return emptyAllowed;
  if (lines.length > 64) return false;
  const records = privateDnsRecordsFromDraft(value);
  return records.length === lines.length
    && lines.every((line) => line.indexOf("=") > 0 && line.indexOf("=") === line.lastIndexOf("="))
    && records.every((record) => (
      privateDnsNameIsValid(record.name) && dnsEndpointAddressIsUsable(record.address)
    ))
    && new Set(records.map((record) => `${record.name}=${record.address.toLowerCase()}`)).size === records.length;
}
