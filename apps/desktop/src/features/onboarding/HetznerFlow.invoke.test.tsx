import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { t } from "../../i18n";
import { HetznerFlow } from "./HetznerFlow";

// The real api and platform layers; only the Tauri bridge is mocked, answering as the desktop commands do.
const native = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ invoke: native.invoke, Channel: class { onmessage = () => {}; } }));
vi.mock("../../lib/confirmAction", () => ({ confirmAction: vi.fn().mockResolvedValue(true) }));
afterEach(cleanup);

const server = { id: 42, name: "sirinvpn-0a1b2c3d", host_key_sha256: `SHA256:${"B".repeat(43)}` };
const token = "hetzner-test-token-0123456789";
const catalog = {
  currency: "EUR", image: "debian-13",
  locations: [{ name: "fsn1", description: "", city: "Falkenstein", country: "DE" }],
  server_types: [{ name: "cx23", description: "cx23", architecture: "x86", cores: 2, memory_gb: 4, disk_gb: 40,
    prices: [{ location: "fsn1", server_monthly: "5.11", ipv4_monthly: "0.60", total_monthly: "5.11" }] }],
};

it("finds the server an uncertain create may have made, through find_hetzner_server", async () => {
  native.invoke.mockImplementation(async (command: string) => {
    switch (command) {
      case "hetzner_catalog": return catalog;
      // A coded desktop rejection is a plain object, not an Error.
      case "create_hetzner_server": throw { message: `Hetzner Cloud may have created server ${server.name}.`, code: "hetzner_create_uncertain", params: { server: server.name } };
      case "find_hetzner_server": return { server, private_key_path: "/config/ssh-keys/sirinvpn-0a1b2c3d" };
      case "wait_hetzner_server": return new Promise(() => {});
      default: return null;
    }
  });
  render(<HetznerFlow onComplete={vi.fn()} />);
  fireEvent.change(screen.getByLabelText(t("onboarding.hetzner.token")), { target: { value: token } });
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.hetzner.loadPlans") }));
  fireEvent.click(await screen.findByRole("button", { name: t("onboarding.hetzner.create", { total: "€5.11" }) }));
  expect(await screen.findByText(t("onboarding.hetzner.uncertain.title", { name: server.name }))).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.hetzner.uncertain.check") }));
  await waitFor(() => expect(native.invoke).toHaveBeenCalledWith("find_hetzner_server", { apiToken: token, name: server.name }));
  fireEvent.click(await screen.findByRole("button", { name: t("onboarding.hetzner.uncertain.adopt") }));
  expect(await screen.findByText(t("onboarding.hetzner.waiting", { name: server.name }))).toBeTruthy();
  expect(native.invoke).toHaveBeenCalledWith("wait_hetzner_server", { apiToken: token, server });
  expect(native.invoke.mock.calls.filter(([command]) => command === "create_hetzner_server")).toHaveLength(1);
});
