import { Field } from "../../components/ui";
import { dnsEndpointAddressIsUsable, privateDnsNameIsValid, privateResolverAddressIsUsable } from "../../dns";
import { validateHost } from "../../format";
import type { DnsSplitZone, DnsUpstream } from "../../types";

export function splitDnsZones(value: string): DnsSplitZone[] {
  const zones = value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line): DnsSplitZone => {
    const [name, resolvers, extra] = line.split("=");
    const suffix = name.trim().toLowerCase().replace(/\.$/, "");
    if (!resolvers || extra !== undefined || !privateDnsNameIsValid(suffix) || suffix.endsWith(".local") || dnsEndpointAddressIsUsable(suffix)) throw Error("Enter a domain suffix and its resolver addresses.");
    const entries = resolvers.split(",").map((entry) => entry.trim());
    if (!entries.length || entries.length > 4 || new Set(entries).size !== entries.length) throw Error("Use one to four unique resolvers per zone.");
    if (resolvers.includes("#")) {
      if (entries.length > 2) throw Error("Use at most two TLS resolvers per zone.");
      const endpoints = entries.map((entry) => {
        const [address, rawName, trailing] = entry.split("#");
        const authentication_name = rawName?.trim().toLowerCase();
        if (!dnsEndpointAddressIsUsable(address) || !authentication_name || trailing !== undefined || !validateHost(authentication_name) || authentication_name.includes(":")) throw Error("Each TLS resolver needs IP#TLS-name.");
        return { address: address.trim(), authentication_name };
      });
      return { suffix, upstream: { mode: "dns_over_tls", endpoints }, allow_unsigned_answers: false };
    }
    if (!entries.every(privateResolverAddressIsUsable)) throw Error("Plain DNS zones require private IPv4 or ULA IPv6 resolver addresses.");
    return { suffix, upstream: { mode: "private", addresses: entries }, allow_unsigned_answers: true };
  });
  if (zones.length > 16 || new Set(zones.map((zone) => zone.suffix)).size !== zones.length) throw Error("Use up to 16 unique domain suffixes.");
  return zones;
}

export function splitDnsDraftIsValid(value: string): boolean {
  try { splitDnsZones(value); return true; } catch { return false; }
}

export function withSplitDns(defaultPolicy: DnsUpstream, value: string): DnsUpstream {
  const zones = splitDnsZones(value);
  return zones.length ? { mode: "split", default: defaultPolicy, zones } : defaultPolicy;
}

export function SplitDnsFields({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  return <Field label="Split DNS zones" hint="Optional. One suffix=resolver per line; separate fallback resolvers with commas. Longest matching suffix wins.">
    <textarea className="private-dns-record-input mono" value={value} onChange={(event) => onChange(event.target.value)}
      placeholder={"office.home=10.20.0.53\ncorp.example=192.0.2.53#dns.example.com"} spellCheck={false} autoCapitalize="none" autoComplete="off" />
    <p className="dns-policy-note">Private-address zones use DNS over TCP from your VPS and allow unsigned private answers. IP#TLS-name uses authenticated TLS with DNSSEC validation. These zones never fall back to the default resolver. All client DNS still travels through the VPN.</p>
    {value && !splitDnsDraftIsValid(value) && <p className="warning-note">Check the zone names and resolver addresses. Up to 16 unique zones are supported.</p>}
  </Field>;
}
