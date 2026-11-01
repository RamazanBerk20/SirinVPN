/** Client-side checks for typed network ranges, so a bad list is flagged at the field instead of saved. */

/** IPv4 "a.b.c.d/n" as an unsigned 32-bit address and prefix, or null. */
export function parseIpv4Cidr(text: string): { address: number; prefix: number } | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(text.trim());
  if (!match) return null;
  const octets = match.slice(1, 5).map(Number);
  const prefix = Number(match[5]);
  if (octets.some((octet) => octet > 255) || prefix > 32) return null;
  return { address: ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0, prefix };
}

/** True when no host bits are set after the prefix: 192.168.1.0/24, not 192.168.1.5/24. */
function canonical({ address, prefix }: { address: number; prefix: number }) {
  const host = prefix === 32 ? 0 : 0xffffffff >>> prefix;
  return ((address & host) >>> 0) === 0;
}

/** IPv6 "x:x::x/n" by shape only (hex groups, at most one "::", prefix up to 128). */
function ipv6Cidr(text: string) {
  const match = /^([0-9a-f:]+)\/(\d{1,3})$/i.exec(text.trim());
  if (!match || Number(match[2]) > 128 || match[1].split("::").length > 2) return false;
  const groups = match[1].split(":").filter(Boolean);
  return groups.length <= 8 && groups.every((group) => group.length <= 4) && (match[1].includes("::") || groups.length === 8);
}

/** Entries of a tunnel route list that are not a network in canonical CIDR form. */
export function invalidRoutes(routes: string[]) {
  return routes.filter((route) => {
    const ipv4 = parseIpv4Cidr(route);
    return ipv4 ? !canonical(ipv4) : !ipv6Cidr(route);
  });
}

/** Entries that are not a canonical private IPv4 network of /20 or smaller (shared local networks). */
export function invalidLocalNetworks(routes: string[]) {
  return routes.filter((route) => {
    const network = parseIpv4Cidr(route);
    if (!network || network.prefix < 20 || !canonical(network)) return true;
    const [first, second] = [network.address >>> 24, (network.address >>> 16) & 0xff];
    return !(first === 10 || first === 172 && second >= 16 && second <= 31 || first === 192 && second === 168);
  });
}
