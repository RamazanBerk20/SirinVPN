import { Field } from "../../components/ui";
import { useInfoHint } from "../../components/InfoHint";
import { dnsEndpointAddressIsUsable, privateDnsNameIsValid, privateResolverAddressIsUsable } from "../../dns";
import { validateHost } from "../../format";
import { t } from "../../i18n";
import type { DnsSplitZone, DnsUpstream } from "../../types";

export function splitDnsZones(value: string): DnsSplitZone[] {
  const invalid = () => Error(t("dns.split.invalid"));
  const zones = value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line): DnsSplitZone => {
    const [name, resolvers, extra] = line.split("=");
    const suffix = name.trim().toLowerCase().replace(/\.$/, "");
    // A suffix needs its resolver addresses.
    if (!resolvers || extra !== undefined || !privateDnsNameIsValid(suffix) || suffix.endsWith(".local") || dnsEndpointAddressIsUsable(suffix)) throw invalid();
    const entries = resolvers.split(",").map((entry) => entry.trim());
    // One to four unique resolvers per zone.
    if (!entries.length || entries.length > 4 || new Set(entries).size !== entries.length) throw invalid();
    if (resolvers.includes("#")) {
      // At most two TLS resolvers per zone, each written as IP#TLS-name.
      if (entries.length > 2) throw invalid();
      const endpoints = entries.map((entry) => {
        const [address, rawName, trailing] = entry.split("#");
        const authentication_name = rawName?.trim().toLowerCase();
        if (!dnsEndpointAddressIsUsable(address) || !authentication_name || trailing !== undefined || !validateHost(authentication_name) || authentication_name.includes(":")) throw invalid();
        return { address: address.trim(), authentication_name };
      });
      return { suffix, upstream: { mode: "dns_over_tls", endpoints }, allow_unsigned_answers: false };
    }
    // Plain DNS zones require private IPv4 or ULA IPv6 resolver addresses.
    if (!entries.every(privateResolverAddressIsUsable)) throw invalid();
    return { suffix, upstream: { mode: "private", addresses: entries }, allow_unsigned_answers: true };
  });
  // Up to 16 unique domain suffixes.
  if (zones.length > 16 || new Set(zones.map((zone) => zone.suffix)).size !== zones.length) throw invalid();
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
  const [info, infoPanel] = useInfoHint(t("dns.split.info"), t("dns.split.infoLabel"));
  return <Field label={t("dns.split.label")}>
    <textarea className="private-dns-record-input mono" aria-label={t("dns.split.label")} value={value} onChange={(event) => onChange(event.target.value)}
      placeholder={"office.home=10.20.0.53\ncorp.example=192.0.2.53#dns.example.com"} spellCheck={false} autoCapitalize="none" autoComplete="off" />
    <p className="dns-policy-note">{t("dns.split.summary")}{info}</p>
    {infoPanel}
    {value && !splitDnsDraftIsValid(value) && <p className="warning-note">{t("dns.split.invalid")}</p>}
  </Field>;
}
