import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import type { NetworkPreflight, ProvisionResult } from "../../types";
import { confirmNavigation } from "../../lib/navigationGuard";
import { SetupFlow } from "./SetupFlow";
import { t } from "../../i18n";

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

async function verifyHost(onComplete = vi.fn()) {
  render(<SetupFlow onComplete={onComplete} />);
  fireEvent.change(screen.getByLabelText(t("onboarding.setup.host")), { target: { value: "vps.example" } });
  const agent = screen.getByRole("button", { name: "SSH agent" });
  await waitFor(() => expect(agent.matches(":disabled")).toBe(false));
  fireEvent.click(agent);
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.setup.verify") }));
  return screen.findByRole("button", { name: t("onboarding.setup.fingerprint.matches") });
}

it("has one fingerprint confirmation and reviews the network before offering installation", async () => {
  const confirm = await verifyHost();
  expect(screen.getAllByRole("button", { name: t("onboarding.setup.fingerprint.matches") })).toHaveLength(1);
  expect(screen.queryByRole("button", { name: t("onboarding.setup.fingerprint.install") })).toBeNull();
  expect(api.inspectServerNetwork).not.toHaveBeenCalled();
  fireEvent.click(confirm);
  const install = await screen.findByRole("button", { name: t("onboarding.setup.fingerprint.install") });
  expect((install as HTMLButtonElement).disabled).toBe(false);
  expect(api.provisionServer).not.toHaveBeenCalled();
  expect(screen.queryByRole("group", { name: t("dns.nat64.legend") })).toBeNull();
});

it("offers NAT64 for a VPS without IPv4 and sends only a well-formed prefix", async () => {
  vi.mocked(api.inspectServerNetwork).mockResolvedValue({ ...report, issues: [{ code: "ipv6_only", blocking: false, message: "This VPS has no IPv4." }] });
  vi.mocked(api.provisionServer).mockResolvedValue(provisioned);
  fireEvent.click(await verifyHost());
  const install = await screen.findByRole("button", { name: t("onboarding.setup.fingerprint.install") }) as HTMLButtonElement;
  const prefix = within(screen.getByRole("group", { name: t("dns.nat64.legend") })).getByRole("textbox");
  expect(install.disabled).toBe(false);
  fireEvent.change(prefix, { target: { value: "nat64.example" } });
  expect(install.disabled).toBe(true);
  fireEvent.change(prefix, { target: { value: " 2a00:1098:2b::/96 " } });
  fireEvent.click(install);
  await waitFor(() => expect(api.provisionServer).toHaveBeenCalledWith(expect.objectContaining({ nat64_prefix: "2a00:1098:2b::/96" })));
});

it("prevents installation when the inspected network has a blocking conflict", async () => {
  vi.mocked(api.inspectServerNetwork).mockResolvedValue({ ...report, issues: [{ code: "ssh_port_conflict", blocking: true, message: "The selected port is occupied." }] });
  fireEvent.click(await verifyHost());
  const install = await screen.findByRole("button", { name: t("onboarding.setup.fingerprint.install") });
  expect((install as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(install);
  expect(api.provisionServer).not.toHaveBeenCalled();
});

const provisioned = {
  profile: { id: "new-server", name: "My VPS" }, dns_upstream: { mode: "recursive" },
  private_dns_records: [], network_preflight: null,
} as unknown as ProvisionResult;

it("blocks navigation while installing and hands an unopened result to the app once on close", async () => {
  let finish!: (result: ProvisionResult) => void;
  vi.mocked(api.provisionServer).mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
  const onComplete = vi.fn().mockResolvedValue(undefined);
  fireEvent.click(await verifyHost(onComplete));
  fireEvent.click(await screen.findByRole("button", { name: t("onboarding.setup.fingerprint.install") }));
  await waitFor(() => expect(api.provisionServer).toHaveBeenCalled());
  expect(confirmNavigation()).toBe(false);
  await act(async () => finish(provisioned));
  await screen.findByRole("button", { name: t("onboarding.setup.success.open") });
  expect(confirmNavigation()).toBe(true);
  expect(onComplete).not.toHaveBeenCalled();
  cleanup();
  expect(onComplete).toHaveBeenCalledExactlyOnceWith(provisioned);
});

it("does not repeat the handoff after Open server", async () => {
  vi.mocked(api.provisionServer).mockResolvedValue(provisioned);
  const onComplete = vi.fn().mockResolvedValue(undefined);
  fireEvent.click(await verifyHost(onComplete));
  fireEvent.click(await screen.findByRole("button", { name: t("onboarding.setup.fingerprint.install") }));
  fireEvent.click(await screen.findByRole("button", { name: t("onboarding.setup.success.open") }));
  cleanup();
  expect(onComplete).toHaveBeenCalledExactlyOnceWith(provisioned);
});

it("keeps a failed install on the install step with what stopped, what changed and both ways on", async () => {
  vi.mocked(api.provisionServer).mockRejectedValueOnce(Object.assign(new Error("server transaction failed during server configuration: apt-get exited with status 100"), { code: "install_phase_failed", params: { phase: "server configuration" } }));
  const onComplete = vi.fn().mockResolvedValue(undefined);
  fireEvent.click(await verifyHost(onComplete));
  fireEvent.click(await screen.findByRole("button", { name: t("onboarding.setup.fingerprint.install") }));
  expect(await screen.findByText(t("onboarding.setup.failed.title"))).toBeTruthy();
  expect(screen.getByText(t("onboarding.setup.failed.stages.configure"))).toBeTruthy();
  expect(screen.getByText(t("onboarding.setup.failed.change.rolledBack"))).toBeTruthy();
  expect(screen.getByText(`SHA256:${"A".repeat(43)}`)).toBeTruthy();
  expect(screen.getByRole("alert").textContent).toContain("apt-get exited with status 100");
  expect(screen.queryByLabelText(t("onboarding.setup.host"))).toBeNull();

  // Back to settings keeps the verified fingerprint and network check: no new probe or check.
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.setup.failed.back") }));
  fireEvent.click(screen.getByRole("button", { name: new RegExp(t("onboarding.setup.continue")) }));
  expect(await screen.findByText(t("onboarding.setup.fingerprint.confirmed"))).toBeTruthy();
  expect(api.probeHostKey).toHaveBeenCalledTimes(1);
  expect(api.inspectServerNetwork).toHaveBeenCalledTimes(1);

  vi.mocked(api.provisionServer).mockResolvedValueOnce(provisioned);
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.setup.fingerprint.install") }));
  fireEvent.click(await screen.findByRole("button", { name: t("onboarding.setup.success.recoveryKey") }));
  expect(onComplete).toHaveBeenCalledExactlyOnceWith(provisioned, "recovery");
});

it("retries a failed install in place", async () => {
  vi.mocked(api.provisionServer).mockRejectedValueOnce(Object.assign(new Error("SSH authentication failed"), { code: "install_ssh_failed", params: {} })).mockResolvedValueOnce(provisioned);
  fireEvent.click(await verifyHost());
  fireEvent.click(await screen.findByRole("button", { name: t("onboarding.setup.fingerprint.install") }));
  expect(await screen.findByText(t("onboarding.setup.failed.change.unchanged"))).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.setup.failed.retry") }));
  expect(await screen.findByText(t("onboarding.setup.success.title"))).toBeTruthy();
  expect(api.provisionServer).toHaveBeenCalledTimes(2);
});

it("labels the network retry and leads a port conflict back to the port field", async () => {
  vi.mocked(api.inspectServerNetwork).mockRejectedValueOnce(new Error("Timed out"));
  fireEvent.click(await verifyHost());
  const again = await screen.findByRole("button", { name: t("onboarding.setup.fingerprint.checkAgain") });
  expect(screen.getByRole("alert").textContent).toContain("Timed out");
  vi.mocked(api.inspectServerNetwork).mockResolvedValueOnce({ ...report, issues: [{ code: "port_in_use", blocking: true, message: "UDP port 51820 is already owned by another service.", params: { protocol: "udp", port: "51820" } }] });
  fireEvent.click(again);
  fireEvent.click(await screen.findByRole("button", { name: t("onboarding.setup.fingerprint.changePort") }));
  const port = await screen.findByRole("textbox", { name: t("ssh.transport.directPort") });
  await waitFor(() => expect(document.activeElement).toBe(port));
  expect((port.closest("details") as HTMLDetailsElement).open).toBe(true);
});
