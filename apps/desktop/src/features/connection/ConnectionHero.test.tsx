import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { emptyLocalStatus } from "../../hooks/useDesktopStatus";
import { t } from "../../i18n";
import type { LocalTunnelStatus, ServerStatus } from "../../types";
import { ConnectionHero } from "./ConnectionHero";
import type { ServerWorkspaceModel } from "./useServerWorkspace";

vi.mock("../../platform", () => ({ isAndroid: false, dpadOnly: false, invoke: vi.fn() }));
vi.mock("../../api", () => ({ api: { localComponentUpdateStatus: async () => ({ install_available: true, update_required: false }) } }));
vi.mock("../settings/vpsBackupSchedules", () => ({ useVpsBackupSchedule: () => null, needsAttention: () => false, backupAge: () => "" }));

afterEach(cleanup);

const connected = { ...emptyLocalStatus, state: "connected" as const, server_id: "a", ipv6_blocked: true };
const model = (localStatus: LocalTunnelStatus, extra: Partial<ServerWorkspaceModel> = {}) => ({
  localStatus, serverStatus: null, busy: false, error: "", connectionOperation: null, presharedKeyMissing: false, rotationPendingConfirmed: false,
  profile: { id: "a", name: "My VPS", role: "owner", endpoint: { host: "vpn.example", wireguard_port: 51820 }, client_tunnel_address: "10.8.0.2" },
  preferences: { saved: { transport: "automatic" } }, freshness: { refreshing: false, updatedAt: 1, management: "ready" },
  toggle: vi.fn(), resume: vi.fn(), onRefresh: vi.fn(), cancelConnection: vi.fn(), runDiagnostics: vi.fn(),
  setTroubleshootOpen: vi.fn(), setRotationOpen: vi.fn(), setVpsBackupScheduleOpen: vi.fn(), ...extra,
}) as unknown as ServerWorkspaceModel;

it("makes Reconnect the ring action of an interrupted connection, with unblocking second", () => {
  const workspace = model({ ...connected, state: "degraded", waiting_for_user: true, kill_switch_enabled: true, kill_switch_state: "blocking" });
  render(<ConnectionHero model={workspace} view="home" />);
  fireEvent.click(screen.getByRole("button", { name: t("home.action.reconnect") }));
  expect(workspace.resume).toHaveBeenCalledOnce();
  fireEvent.click(screen.getByRole("button", { name: t("home.action.disconnectAndUnblock") }));
  expect(workspace.toggle).toHaveBeenCalledOnce();
  expect(document.querySelector(".connection-console")?.getAttribute("data-tone")).toBe("warn");
});

it("says it is checking instead of offering a refresh before the first status", () => {
  render(<ConnectionHero model={model({ ...emptyLocalStatus, state: "unknown" }, { freshness: { refreshing: true, updatedAt: null, management: "idle" } })} view="home" />);
  expect(screen.getByRole("status").textContent).toBe(t("home.status.checking"));
  expect((screen.getByRole("button", { name: t("home.status.checking") }) as HTMLButtonElement).disabled).toBe(true);
});

it("turns a server fault into an amber alert with a way to act on it", () => {
  const open = vi.fn();
  render(<ConnectionHero model={model(connected, { serverStatus: { interface_up: false, dns_healthy: true } as ServerStatus })} view="home" onOpenMaintenance={open} />);
  expect(screen.getByText(t("home.warning.serverInterfaceDown"))).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("home.alert.checkServer") }));
  expect(open).toHaveBeenCalledOnce();
  expect(document.querySelector(".connection-console")?.getAttribute("data-tone")).toBe("warn");
});
