import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import { confirmAction } from "../../lib/confirmAction";
import { confirmNavigation } from "../../lib/navigationGuard";
import type { CreatedHetznerServer, HetznerCatalog } from "../../types";
import { t } from "../../i18n";
import { HetznerFlow, plansFor } from "./HetznerFlow";

const platform = vi.hoisted(() => ({ android: false, invoke: vi.fn() }));
vi.mock("../../platform", async importOriginal => ({
  ...await importOriginal<typeof import("../../platform")>(),
  get isAndroid() { return platform.android; },
  invoke: platform.invoke,
}));
vi.mock("../../lib/confirmAction", () => ({ confirmAction: vi.fn() }));
vi.mock("../../api", () => ({ api: {
  hetznerCatalog: vi.fn(), createHetznerServer: vi.fn(), waitHetznerServer: vi.fn(),
  cancelHetznerWait: vi.fn(), deleteHetznerServer: vi.fn(),
  getSshLogin: vi.fn(), saveSshLogin: vi.fn(), forgetSshLogin: vi.fn(), inspectServerNetwork: vi.fn(), provisionServer: vi.fn(),
} }));

const price = (location: string, total: string) => ({ location, server_monthly: total, ipv4_monthly: "0.60", total_monthly: total });
const type = (name: string, architecture: "x86" | "arm", prices: ReturnType<typeof price>[]) =>
  ({ name, description: name, architecture, cores: 2, memory_gb: 4, disk_gb: 40, prices });
const catalog: HetznerCatalog = {
  currency: "EUR", image: "debian-13",
  locations: [{ name: "fsn1", description: "", city: "Falkenstein", country: "DE" }, { name: "ash", description: "", city: "Ashburn", country: "US" }],
  server_types: [
    type("cpx22", "x86", [price("fsn1", "8.93")]),
    type("cax11", "arm", [price("fsn1", "4.70")]),
    type("cx23", "x86", [price("fsn1", "5.11"), price("ash", "6.45")]),
  ],
};
const server = { id: 42, name: "sirinvpn-0a1b2c3d", host_key_sha256: `SHA256:${"B".repeat(43)}` };
const token = "hetzner-test-token-0123456789";

beforeEach(() => {
  vi.resetAllMocks();
  platform.android = false;
  vi.mocked(api.hetznerCatalog).mockResolvedValue(structuredClone(catalog));
  vi.mocked(api.createHetznerServer).mockResolvedValue({ server, private_key_path: "/config/ssh-keys/sirinvpn-0a1b2c3d" });
  vi.mocked(api.getSshLogin).mockResolvedValue(null);
  vi.mocked(confirmAction).mockResolvedValue(true);
});
afterEach(() => { cleanup(); vi.useRealTimers(); });

async function showPlans() {
  render(<HetznerFlow onComplete={vi.fn()} />);
  fireEvent.change(screen.getByLabelText(t("onboarding.hetzner.token")), { target: { value: token } });
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.hetzner.loadPlans") }));
  return screen.findByRole("button", { name: t("onboarding.hetzner.create", { total: "5.11", currency: "EUR" }) });
}

it("defaults to the cheapest x86 type and lists Arm after x86", () => {
  expect(plansFor(catalog, "fsn1").map(item => item.name)).toEqual(["cx23", "cpx22", "cax11"]);
  expect(plansFor(catalog, "ash").map(item => item.name)).toEqual(["cx23"]);
});

it("shows the monthly price and creates nothing until the Owner confirms it", async () => {
  const create = await showPlans();
  expect(api.hetznerCatalog).toHaveBeenCalledWith(token);
  expect(screen.getByRole("status").textContent).toContain(t("onboarding.hetzner.price", { total: "5.11", currency: "EUR", server: "5.11", ipv4: "0.60" }));
  vi.mocked(confirmAction).mockResolvedValueOnce(false);
  fireEvent.click(create);
  await waitFor(() => expect(confirmAction).toHaveBeenCalled());
  expect(api.createHetznerServer).not.toHaveBeenCalled();
});

it("creates, waits for the pinned key and hands the server to the installer", async () => {
  const replaced = `SHA256:${"C".repeat(43)}`;
  vi.mocked(api.waitHetznerServer).mockResolvedValue({ ipv4: "203.0.113.7", ipv6: "2001:db8::1", host_key_sha256: replaced });
  fireEvent.click(await showPlans());
  await waitFor(() => expect(api.createHetznerServer).toHaveBeenCalledWith(token, { location: "fsn1", server_type: "cx23", accepted_monthly_price: "5.11" }));
  expect(api.waitHetznerServer).toHaveBeenCalledWith(token, server);
  const host = await screen.findByLabelText(t("onboarding.setup.host"));
  expect((host as HTMLInputElement).value).toBe("203.0.113.7");
  expect((host as HTMLInputElement).disabled).toBe(true);
  // The generated key is filled in once the saved-login lookup finishes.
  await waitFor(() => expect(screen.getByDisplayValue("/config/ssh-keys/sirinvpn-0a1b2c3d")).toBeTruthy());
  expect(screen.getByRole("button", { name: t("onboarding.hetzner.delete") })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.setup.verify") }));
  expect(await screen.findByText(t("onboarding.setup.fingerprint.pinned"))).toBeTruthy();
  // The installer pins the key that replaced the pre-seeded one.
  expect(screen.getByText(replaced)).toBeTruthy();
  expect(screen.queryByText(server.host_key_sha256)).toBeNull();
});

it("does not let the Owner leave while the server is being created", async () => {
  let finish!: (value: CreatedHetznerServer) => void;
  vi.mocked(api.createHetznerServer).mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  vi.mocked(api.waitHetznerServer).mockImplementation(() => new Promise(() => {}));
  fireEvent.click(await showPlans());
  expect(await screen.findByText(t("onboarding.hetzner.creating"))).toBeTruthy();
  expect(confirmNavigation()).toBe(false);
  await act(async () => finish({ server, private_key_path: null }));
  expect(await screen.findByText(t("onboarding.hetzner.waiting", { name: server.name }))).toBeTruthy();
  expect(confirmNavigation()).toBe(false);
});

it("asks for the token again once Android has forgotten it", async () => {
  platform.android = true;
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(0);
  platform.invoke.mockResolvedValueOnce("native-secret:first").mockResolvedValueOnce("native-secret:second");
  vi.mocked(api.waitHetznerServer).mockRejectedValue(new Error("the server did not start in time"));
  const enter = () => fireEvent.click(screen.getByRole("button", { name: t("app.secret.enterLabel", { label: t("onboarding.hetzner.token") }) }));
  render(<HetznerFlow onComplete={vi.fn()} />);
  enter();
  fireEvent.click(await screen.findByRole("button", { name: t("onboarding.hetzner.loadPlans") }));
  fireEvent.click(await screen.findByRole("button", { name: t("onboarding.hetzner.create", { total: "5.11", currency: "EUR" }) }));
  expect(await screen.findByText("the server did not start in time")).toBeTruthy();

  vi.setSystemTime(600_000);
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.hetzner.delete") }));
  expect(await screen.findByText(t("onboarding.hetzner.tokenExpired"))).toBeTruthy();
  expect((screen.getByRole("button", { name: t("onboarding.hetzner.delete") }) as HTMLButtonElement).disabled).toBe(true);
  expect(api.deleteHetznerServer).not.toHaveBeenCalled();

  enter();
  await waitFor(() => expect((screen.getByRole("button", { name: t("onboarding.hetzner.delete") }) as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.hetzner.delete") }));
  await waitFor(() => expect(api.deleteHetznerServer).toHaveBeenCalledWith("native-secret:second", server));
});

it("shows the created server when the Android token expires during creation", async () => {
  platform.android = true;
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(0);
  platform.invoke.mockResolvedValueOnce("native-secret:first");
  vi.mocked(api.createHetznerServer).mockImplementation(async () => {
    vi.setSystemTime(600_000);
    return { server, private_key_path: null };
  });
  render(<HetznerFlow onComplete={vi.fn()} />);
  fireEvent.click(screen.getByRole("button", { name: t("app.secret.enterLabel", { label: t("onboarding.hetzner.token") }) }));
  fireEvent.click(await screen.findByRole("button", { name: t("onboarding.hetzner.loadPlans") }));
  fireEvent.click(await screen.findByRole("button", { name: t("onboarding.hetzner.create", { total: "5.11", currency: "EUR" }) }));
  expect(await screen.findByText(t("onboarding.hetzner.failedTitle", { name: server.name }))).toBeTruthy();
  expect(screen.getByText(t("onboarding.hetzner.tokenExpired"))).toBeTruthy();
  expect(api.waitHetznerServer).not.toHaveBeenCalled();
});

it("asks before deleting a server that was cancelled or failed to start", async () => {
  let fail!: (reason: Error) => void;
  vi.mocked(api.waitHetznerServer).mockImplementation(() => new Promise((_, reject) => { fail = reject; }));
  fireEvent.click(await showPlans());
  const stop = await screen.findByRole("button", { name: t("onboarding.hetzner.cancel") });
  fireEvent.click(stop);
  expect(api.cancelHetznerWait).toHaveBeenCalled();
  await act(async () => fail(new Error("server creation was cancelled")));
  expect(await screen.findByText("server creation was cancelled")).toBeTruthy();
  expect(api.deleteHetznerServer).not.toHaveBeenCalled();

  vi.mocked(confirmAction).mockResolvedValueOnce(false);
  fireEvent.click(screen.getByRole("button", { name: t("onboarding.hetzner.delete") }));
  await waitFor(() => expect(confirmAction).toHaveBeenCalledTimes(2));
  expect(api.deleteHetznerServer).not.toHaveBeenCalled();

  fireEvent.click(screen.getByRole("button", { name: t("onboarding.hetzner.delete") }));
  expect(await screen.findByText(t("onboarding.hetzner.deleted", { name: server.name }))).toBeTruthy();
  expect(api.deleteHetznerServer).toHaveBeenCalledExactlyOnceWith(token, server);
});
