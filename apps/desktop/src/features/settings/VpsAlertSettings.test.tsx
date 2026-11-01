import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { VpsAlertSettings } from "./VpsAlertSettings";
import { api } from "../../api";
import { t } from "../../i18n";
import type { AlertSettings } from "../../types";

vi.mock("../../api", () => ({ api: { serverConfiguration: vi.fn(), alertSettings: vi.fn(), updateAlerts: vi.fn(), sendTestAlert: vi.fn() } }));

const owner = { id: "fixture", role: "owner" as const };
const settings = (overrides: Partial<AlertSettings> = {}): AlertSettings => ({
  policy: { format: "ntfy" },
  status: { checked_at_unix: null, alert_sent_at_unix: null, alert_failure: null, heartbeat_sent_at_unix: null, heartbeat_failure: null },
  ...overrides,
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.serverConfiguration).mockResolvedValue({ alerts_enabled: true });
  vi.mocked(api.alertSettings).mockResolvedValue(settings());
});
afterEach(cleanup);

it("is hidden from Admins and Members and never reads the Owner-only settings", () => {
  const view = render(<VpsAlertSettings profile={{ id: "fixture", role: "member" }} connected />);
  expect(view.container.innerHTML).toBe("");
  expect(api.alertSettings).not.toHaveBeenCalled();
});

it("saves HTTPS addresses and tests only what is saved", async () => {
  const saved = settings({ policy: { format: "webhook", alert_url: "https://hooks.example/a?token=x", heartbeat_url: "https://ping.example/abc", allow_private_addresses: false } });
  vi.mocked(api.updateAlerts).mockResolvedValue(saved);
  vi.mocked(api.sendTestAlert).mockResolvedValue({ failure: "rejected", http_status: 403 });
  render(<VpsAlertSettings profile={owner} connected />);
  const save = await screen.findByRole("button", { name: t("vps.alerts.save") });
  const test = screen.getByRole("button", { name: t("vps.alerts.test") });
  expect((save as HTMLButtonElement).disabled).toBe(true);
  expect((test as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByRole("radio", { name: new RegExp(t("vps.alerts.formats.webhook.label")) }));
  fireEvent.change(screen.getByLabelText(t("vps.alerts.alertUrl"), { exact: false }), { target: { value: "http://hooks.example/a" } });
  expect(screen.getByText(t("vps.alerts.invalid"))).toBeTruthy();
  expect((save as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(screen.getByLabelText(t("vps.alerts.alertUrl"), { exact: false }), { target: { value: "https://hooks.example/a?token=x  " } });
  fireEvent.change(screen.getByLabelText(t("vps.alerts.heartbeatUrl"), { exact: false }), { target: { value: "https://ping.example/abc" } });
  expect((test as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(save);
  await waitFor(() => expect(api.updateAlerts).toHaveBeenCalledWith("fixture", {
    format: "webhook",
    alert_url: "https://hooks.example/a?token=x",
    heartbeat_url: "https://ping.example/abc",
    allow_private_addresses: false,
  }));
  expect(await screen.findByText(t("vps.alerts.saved"))).toBeTruthy();
  await waitFor(() => expect((test as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(test);
  expect(await screen.findByText(t("vps.alerts.failure.rejectedStatus", { status: 403 }))).toBeTruthy();
});

it("reports what the VPS check last saw", async () => {
  vi.mocked(api.alertSettings).mockResolvedValue(settings({
    policy: { format: "ntfy", alert_url: "https://ntfy.example/topic", heartbeat_url: "https://ping.example/abc" },
    status: { checked_at_unix: 1_790_000_000, alert_sent_at_unix: null, alert_failure: "connection", heartbeat_sent_at_unix: null, heartbeat_failure: "address" },
  }));
  render(<VpsAlertSettings profile={owner} connected />);
  expect(await screen.findByText(t("vps.alerts.status.alertFailed", { reason: t("vps.alerts.failure.connection") }))).toBeTruthy();
  expect(screen.getByText(t("vps.alerts.status.heartbeatFailed", { reason: t("vps.alerts.failure.address") }))).toBeTruthy();
});

it("asks for a repair when the server lacks the alert timer", async () => {
  vi.mocked(api.serverConfiguration).mockResolvedValue({});
  render(<VpsAlertSettings profile={owner} connected />);
  expect(await screen.findByText(t("vps.alerts.unsupported"))).toBeTruthy();
  expect(api.alertSettings).not.toHaveBeenCalled();
});
