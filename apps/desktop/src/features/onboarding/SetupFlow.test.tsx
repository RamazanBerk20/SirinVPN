import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import type { NetworkPreflight } from "../../types";
import { SetupFlow } from "./SetupFlow";

vi.mock("../../api", () => ({ api: {
  getSshLogin: vi.fn(), saveSshLogin: vi.fn(), forgetSshLogin: vi.fn(),
  probeHostKey: vi.fn(), inspectServerNetwork: vi.fn(), provisionServer: vi.fn(),
} }));
const report: NetworkPreflight = {
  public_endpoint: "vps.example", endpoint_addresses: ["192.0.2.1"], ssh_local_address: null,
  exposure: "public_interface", assigned_addresses: [], required_ports: [{ protocol: "udp", port: 51820 }], issues: [],
};
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.getSshLogin).mockResolvedValue(null);
  vi.mocked(api.saveSshLogin).mockResolvedValue({ username: "root", ssh_port: 22, authentication: "agent", private_key_path: null });
  vi.mocked(api.probeHostKey).mockResolvedValue(`SHA256:${"A".repeat(43)}`);
  vi.mocked(api.inspectServerNetwork).mockResolvedValue(structuredClone(report));
});
afterEach(cleanup);

async function verifyHost() {
  render(<SetupFlow onComplete={vi.fn()} />);
  fireEvent.change(screen.getByLabelText("IP address or hostname"), { target: { value: "vps.example" } });
  const agent = screen.getByRole("button", { name: "SSH agent" });
  await waitFor(() => expect(agent.matches(":disabled")).toBe(false));
  fireEvent.click(agent);
  fireEvent.click(screen.getByRole("button", { name: "Verify VPS" }));
  return screen.findByRole("button", { name: "Fingerprint matches — inspect network" });
}

it("has one fingerprint confirmation and reviews the network before offering installation", async () => {
  const confirm = await verifyHost();
  expect(screen.getAllByRole("button", { name: /Fingerprint matches/ })).toHaveLength(1);
  expect(screen.queryByRole("button", { name: "Install SirinVPN" })).toBeNull();
  expect(api.inspectServerNetwork).not.toHaveBeenCalled();
  fireEvent.click(confirm);
  const install = await screen.findByRole("button", { name: "Install SirinVPN" });
  expect((install as HTMLButtonElement).disabled).toBe(false);
  expect(api.provisionServer).not.toHaveBeenCalled();
});

it("prevents installation when the inspected network has a blocking conflict", async () => {
  vi.mocked(api.inspectServerNetwork).mockResolvedValue({ ...report, issues: [{ code: "port_conflict", blocking: true, message: "The selected port is occupied." }] });
  fireEvent.click(await verifyHost());
  const install = await screen.findByRole("button", { name: "Install SirinVPN" });
  expect((install as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(install);
  expect(api.provisionServer).not.toHaveBeenCalled();
});
