import { expect, it } from "vitest";
import { splitDnsDraftIsValid, withSplitDns } from "./SplitDnsFields";

it("keeps encrypted default DNS and explicitly scopes unsigned private zones", () => {
  const policy = withSplitDns({ mode: "dns_over_https", endpoints: [{ address: "192.0.2.1", authentication_name: "dns.example", path: "/dns-query" }] }, "office.home=10.20.0.53\ncorp.example=192.0.2.53#resolver.example");
  expect(policy.mode).toBe("split");
  if (policy.mode !== "split") throw Error("split policy missing");
  expect(policy.default.mode).toBe("dns_over_https");
  expect(policy.zones.map((zone) => zone.allow_unsigned_answers)).toEqual([true, false]);
});

it("rejects global interception, plaintext public resolvers and mixed fallback modes", () => {
  for (const value of [".=10.20.0.1", "office.home=1.1.1.1", "office.home=10.77.0.1", "office.home=10.77.0.254", "office.home=10.20.0.1#dns.example,10.20.0.2", "office.home=10.20.0.1\noffice.home=10.20.0.2"]) expect(splitDnsDraftIsValid(value)).toBe(false);
});
