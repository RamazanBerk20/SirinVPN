import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import type { NetworkPreflight } from "../../types";
import { ServerNetworkPreflight } from "./ServerNetworkPreflight";
import { t } from "../../i18n";

afterEach(cleanup);
const report: NetworkPreflight = {
  public_endpoint: "vpn.example", endpoint_addresses: ["8.8.8.8"], ssh_local_address: "10.2.0.4",
  exposure: "nat_or_proxy", assigned_addresses: [{ interface: "eth0", address: "10.2.0.4", prefix_length: 24, public: false }],
  required_ports: [{ protocol: "udp", port: 51820 }, { protocol: "tcp", port: 7443 }],
  issues: [{ code: "nat_or_proxy", blocking: false, message: "Forward these ports through the provider NAT mapping." }],
};
it("shows the inspected address mapping and exact provider port requirements", () => {
  render(<ServerNetworkPreflight report={report} />);
  expect(screen.getByRole("heading", { name: t("ssh.network.title") })).toBeTruthy();
  expect(screen.getByLabelText(t("ssh.network.port", { protocol: "UDP", port: 51820 }))).toBeTruthy();
  expect(screen.getByLabelText(t("ssh.network.port", { protocol: "TCP", port: 7443 }))).toBeTruthy();
  expect(screen.getByText("10.2.0.4/24")).toBeTruthy();
  expect(screen.getByText("Forward these ports through the provider NAT mapping.")).toBeTruthy();
});
it("makes an occupied port an actionable conflict", () => {
  render(<ServerNetworkPreflight report={{ ...report, issues: [{ code: "port_in_use", blocking: true, message: "TCP port 7443 is occupied. Choose a free port." }] }} />);
  expect(screen.getByRole("heading", { name: t("ssh.network.titleConflicts") })).toBeTruthy();
  expect(screen.getByText("TCP port 7443 is occupied. Choose a free port.")).toBeTruthy();
});
