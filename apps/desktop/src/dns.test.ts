import { describe, expect, it } from "vitest";
import {
  dnsEndpointAddressIsUsable,
  dnsOverHttpsPathIsValid,
  privateDnsDraftIsValid,
  privateDnsRecordsFromDraft,
} from "./dns";

describe("private DNS record drafts", () => {
  it("normalizes names and accepts bounded A and AAAA records", () => {
    const draft = " NAS.Home. = 10.20.30.40\nserver.home=fd00::10 ";
    expect(privateDnsDraftIsValid(draft, false)).toBe(true);
    expect(privateDnsRecordsFromDraft(draft)).toEqual([
      { name: "nas.home", address: "10.20.30.40" },
      { name: "server.home", address: "fd00::10" },
    ]);
  });

  it("validates exact resolver addresses and bounded HTTPS paths", () => {
    expect(dnsEndpointAddressIsUsable("1.1.1.1")).toBe(true);
    expect(dnsEndpointAddressIsUsable("2606:4700:4700::1111")).toBe(true);
    expect(dnsEndpointAddressIsUsable("127.0.0.1")).toBe(false);
    expect(dnsEndpointAddressIsUsable("fe80::1")).toBe(false);
    expect(dnsOverHttpsPathIsValid("/dns-query")).toBe(true);
    expect(dnsOverHttpsPathIsValid("/resolve%2Fwire")).toBe(true);
    expect(dnsOverHttpsPathIsValid("dns-query")).toBe(false);
    expect(dnsOverHttpsPathIsValid("/dns-query?name=example.com")).toBe(false);
    expect(dnsOverHttpsPathIsValid("/dns query")).toBe(false);
    expect(dnsOverHttpsPathIsValid(`/${"a".repeat(255)}`)).toBe(false);
  });

  it("distinguishes optional empty input from explicit replacement", () => {
    expect(privateDnsDraftIsValid("", true)).toBe(true);
    expect(privateDnsDraftIsValid("", false)).toBe(false);
  });

  it("rejects malformed, unsafe, duplicate, and unbounded records", () => {
    expect(privateDnsDraftIsValid("single=10.0.0.1", false)).toBe(false);
    expect(privateDnsDraftIsValid("bad_name.home=10.0.0.1", false)).toBe(false);
    expect(privateDnsDraftIsValid("host.home=127.0.0.1", false)).toBe(false);
    expect(privateDnsDraftIsValid("host.home=0.0.0.1", false)).toBe(false);
    expect(privateDnsDraftIsValid("host.home=240.0.0.1", false)).toBe(false);
    expect(privateDnsDraftIsValid("host.home=::::", false)).toBe(false);
    expect(privateDnsDraftIsValid("host.home=1:2:3", false)).toBe(false);
    expect(privateDnsDraftIsValid("host.home=fe80::1", false)).toBe(false);
    expect(privateDnsDraftIsValid("host.localhost=10.0.0.1", false)).toBe(false);
    expect(privateDnsDraftIsValid("nas.home=10.0.0.1\nnas.home=10.0.0.1", false)).toBe(false);
    expect(privateDnsDraftIsValid(
      Array.from({ length: 65 }, (_, index) => `host-${index}.home=10.0.0.1`).join("\n"),
      false,
    )).toBe(false);
  });
});
