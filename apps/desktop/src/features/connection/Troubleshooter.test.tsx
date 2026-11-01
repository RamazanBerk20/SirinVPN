import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { t } from "../../i18n";
import { Troubleshooter } from "./Troubleshooter";
import type { ServerWorkspaceModel } from "./useServerWorkspace";

const diagnostics = vi.hoisted(() => vi.fn());
vi.mock("../../api", () => ({ api: { diagnostics } }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });

const workspace = (transport: string) => ({
  troubleshootOpen: true, setTroubleshootOpen: vi.fn(), rotationPending: false,
  profile: { id: "server", role: "owner", endpoint: { host: "vpn.example.com", wireguard_port: 51820 } },
  preferences: { saved: { transport } },
  setEndpointUpdateOpen: vi.fn(), setMaintenanceReview: vi.fn(), setRotationOpen: vi.fn(),
}) as unknown as ServerWorkspaceModel;

it("opens at the likely cause, steps through the others and hands off to its fix", async () => {
  diagnostics.mockResolvedValue({ api_version: "v1", checks: [{ code: "local_tunnel", label: "Tunnel", level: "fail", message: "No usable connection." }] });
  const model = workspace("direct_udp");
  const onOpenSettings = vi.fn();
  render(<Troubleshooter model={model} onOpenSettings={onOpenSettings} onRestoreDevice={vi.fn()} />);
  expect(await screen.findByText(t("help.troubleshoot.step.transport"))).toBeTruthy();
  expect(screen.getByText(t("common.separator.pair", { first: t("help.troubleshoot.progress", { current: 4, total: 8 }), second: t("help.troubleshoot.status.problem") }))).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("common.action.back") }));
  expect(screen.getByText(t("help.troubleshoot.step.reachability"))).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("help.troubleshoot.next") }));
  fireEvent.click(screen.getByRole("button", { name: t("help.troubleshoot.connectionSettings") }));
  expect(model.setTroubleshootOpen).toHaveBeenCalledWith(false);
  expect(onOpenSettings).toHaveBeenCalledWith("connection");
  expect(diagnostics).toHaveBeenCalledWith("server");
});

it("still walks every step when diagnostics are unavailable", async () => {
  diagnostics.mockRejectedValue(new Error("busy"));
  render(<Troubleshooter model={workspace("automatic")} onOpenSettings={vi.fn()} onRestoreDevice={vi.fn()} />);
  expect(await screen.findByText(t("help.troubleshoot.step.network"))).toBeTruthy();
  expect(screen.getByText(t("help.troubleshoot.network.check"))).toBeTruthy();
  for (let step = 1; step < 8; step++) fireEvent.click(screen.getByRole("button", { name: t("help.troubleshoot.next") }));
  expect(screen.getByText(t("help.troubleshoot.step.service"))).toBeTruthy();
  expect(screen.getByRole("button", { name: t("common.action.done") })).toBeTruthy();
});
