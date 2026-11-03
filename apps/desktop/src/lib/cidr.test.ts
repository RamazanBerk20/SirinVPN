import { expect, it } from "vitest";
import { canonicalIpv4, invalidLocalNetworks, invalidRoutes, parseIpv4Cidr } from "./cidr";

it("parses IPv4 networks and rejects malformed ones", () => {
  expect(parseIpv4Cidr("198.51.100.0/24")).toEqual({ address: 0xc6336400, prefix: 24 });
  for (const bad of ["198.51.100.0", "256.0.0.0/8", "10.0.0.0/33", "not-a-route", "10.0.0.0/ 8"]) expect(parseIpv4Cidr(bad)).toBeNull();
});

it("flags tunnel routes that are not canonical CIDR networks", () => {
  expect(invalidRoutes(["198.51.100.0/24", "203.0.113.40/32", "0.0.0.0/0", "2001:db8:1234::/48", "::/0"])).toEqual([]);
  expect(invalidRoutes(["198.51.100.7/24", "not-a-route", "2001:db8::1::/64", "2001:db8::/129"])).toEqual(["198.51.100.7/24", "not-a-route", "2001:db8::1::/64", "2001:db8::/129"]);
});

it("accepts only private IPv4 networks of /20 or smaller for shared local networks", () => {
  expect(invalidLocalNetworks(["192.168.1.0/24", "10.20.0.0/20", "172.31.255.0/24"])).toEqual([]);
  expect(invalidLocalNetworks(["192.168.0.0/8", "10.0.0.0/16", "198.51.100.0/24", "192.168.1.5/24", "172.32.0.0/24", "not a network"]))
    .toEqual(["192.168.0.0/8", "10.0.0.0/16", "198.51.100.0/24", "192.168.1.5/24", "172.32.0.0/24", "not a network"]);
});

it("suggests the network a range with host bits belongs to", () => {
  expect(canonicalIpv4("198.51.100.7/24")).toBe("198.51.100.0/24");
  expect(canonicalIpv4("10.1.2.3/8")).toBe("10.0.0.0/8");
  expect(canonicalIpv4("198.51.100.0/24")).toBeNull();
  expect(canonicalIpv4("not a range")).toBeNull();
});
