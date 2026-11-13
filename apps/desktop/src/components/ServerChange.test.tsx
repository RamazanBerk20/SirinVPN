import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api, type InstallPlan } from "../api";
import { t } from "../i18n";
import { OperationPlan, ServerChangeFailure } from "./ServerChange";

vi.mock("../api", () => ({ api: { resolveInstallTransaction: vi.fn(), abandonInstallTransaction: vi.fn() } }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });
const coded = (code: string, params: Record<string, unknown>) => Object.assign(new Error("Backend text."), { code, params });

it("lists each reason blocked maintenance gives, in the interface language", () => {
  render(<ServerChangeFailure reason={coded("maintenance_blocked", { blockers: ["connected", "something_new"], messages: ["Disconnect first.", "Do the new thing."] })} message="Generic." />);
  // A blocker this version doesn't know keeps the backend's sentence.
  expect(screen.getAllByRole("listitem").map((item) => item.textContent)).toEqual([t("common.maintenanceBlocker.connected"), "Do the new thing."]);
  expect(screen.queryByText("Generic.")).toBeNull();
});

it("checks an unknown outcome again and says how it ended", async () => {
  vi.mocked(api.resolveInstallTransaction).mockResolvedValueOnce({ transaction: "n", host: "203.0.113.1", port: 22, operation: "install", step: "commit_sent", server_id: null, state: "rolled_back" } as never);
  const resolved = vi.fn();
  render(<ServerChangeFailure reason={coded("install_outcome_unknown", { host: "203.0.113.1", reason: "timeout" })} message="Generic." onResolved={resolved} />);
  expect(screen.getByText(t("vps.change.unknown.message", { host: "203.0.113.1" }))).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("vps.change.unknown.checkAgain") }));
  expect(await screen.findByText(t("vps.change.rolledBack"))).toBeTruthy();
  expect(api.resolveInstallTransaction).toHaveBeenCalledWith({}, "203.0.113.1");
  expect(resolved).toHaveBeenCalled();
});

it("forgets an unresolved change only after a plain confirmation", async () => {
  vi.mocked(api.abandonInstallTransaction).mockResolvedValueOnce({ host: "203.0.113.1", state: "abandoned", keys_kept: true });
  const resolved = vi.fn();
  render(<ServerChangeFailure reason={coded("transaction_unresolved", { host: "203.0.113.1" })} message="Generic." onResolved={resolved} />);
  expect(screen.getByText(t("common.errorCode.transaction_unresolved", { host: "203.0.113.1" }))).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("vps.change.unknown.forget") }));
  expect(screen.getByText(t("vps.change.unknown.forgetMessage"))).toBeTruthy();
  expect(api.abandonInstallTransaction).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: t("vps.change.unknown.forgetConfirm") }));
  expect(await screen.findByText(t("vps.change.unknown.forgotten", { host: "203.0.113.1" }))).toBeTruthy();
  expect(api.abandonInstallTransaction).toHaveBeenCalledWith("203.0.113.1");
  expect(resolved).toHaveBeenCalled();
});

it("shows any other failure as its message", () => {
  render(<ServerChangeFailure reason={new Error("x")} message="Couldn’t repair the server." />);
  expect(screen.getByRole("alert").textContent).toContain("Couldn’t repair the server.");
});

it("loads the plan when opened and lists its commands and files", async () => {
  const plan: InstallPlan = { operation: "repair", host: "h", nonce: "n", discovery: null, network_preflight: null, managed_paths: ["etc/sirinvpn"],
    steps: [{ kind: "run", privileged: true, command: "systemctl restart sirinvpn", stdin_bytes: null }, { kind: "deferred", description: "Commit the change" }] };
  const load = vi.fn().mockResolvedValue(plan);
  const { container } = render(<OperationPlan load={load} />);
  expect(load).not.toHaveBeenCalled();
  const details = container.querySelector("details")!;
  details.open = true;
  fireEvent(details, new Event("toggle"));
  expect(await screen.findByText("systemctl restart sirinvpn")).toBeTruthy();
  expect(screen.getByText("Commit the change")).toBeTruthy();
  expect(screen.getByText("/etc/sirinvpn")).toBeTruthy();
});
