import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { DnsBlocklistSettings } from "./DnsBlocklistSettings";
import { api } from "../../api";
import { t } from "../../i18n";
import type { DnsBlocklistSettings as Settings } from "../../types";

vi.mock("../../api", () => ({ api: { serverConfiguration: vi.fn(), dnsBlocklistSettings: vi.fn(), updateDnsBlocklist: vi.fn() } }));

const light = { name: "Fixture Light", url: "https://lists.example/light.txt" };
const settings = (overrides: Partial<Settings> = {}): Settings => ({
  policy: { enabled: false },
  status: { active: false, domain_count: 0, updated_at_unix: null, failure: null },
  pending: false,
  presets: [light, { name: "Fixture Hosts", url: "https://lists.example/hosts" }],
  ...overrides,
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.serverConfiguration).mockResolvedValue({ dns_blocklist_management_enabled: true });
  vi.mocked(api.dnsBlocklistSettings).mockResolvedValue(settings());
});
afterEach(cleanup);

it("is hidden from members and never reads the manager-only settings", () => {
  const view = render(<DnsBlocklistSettings profile={{ id: "fixture" }} connected canManage={false} />);
  expect(view.container.innerHTML).toBe("");
  expect(api.dnsBlocklistSettings).not.toHaveBeenCalled();
});

it("saves the chosen lists and normalized allowed domains for every device", async () => {
  vi.mocked(api.updateDnsBlocklist).mockResolvedValue(settings({
    policy: { enabled: true, sources: [light.url, "https://own.example/list.txt"], allowlist: ["cdn.example.com"] },
    pending: true,
  }));
  render(<DnsBlocklistSettings profile={{ id: "fixture" }} connected canManage />);
  const save = await screen.findByRole("button", { name: t("dns.blocklist.save") });
  fireEvent.click(screen.getByRole("checkbox", { name: t("dns.blocklist.enable") }));
  expect((save as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByRole("checkbox", { name: light.name }));
  fireEvent.change(screen.getByLabelText(t("dns.blocklist.custom"), { exact: false }), { target: { value: "http://own.example/list.txt" } });
  expect(screen.getByText(t("dns.blocklist.customInvalid"))).toBeTruthy();
  fireEvent.change(screen.getByLabelText(t("dns.blocklist.custom"), { exact: false }), { target: { value: "https://own.example/list.txt\n" } });
  fireEvent.change(screen.getByLabelText(t("dns.blocklist.allowlist"), { exact: false }), { target: { value: "CDN.Example.com.\ncdn.example.com" } });
  fireEvent.click(save);
  await waitFor(() => expect(api.updateDnsBlocklist).toHaveBeenCalledWith("fixture", {
    enabled: true,
    sources: [light.url, "https://own.example/list.txt"],
    allowlist: ["cdn.example.com"],
  }));
  expect(await screen.findByText(t("dns.blocklist.status.pending"))).toBeTruthy();
  expect(screen.getByText(t("dns.blocklist.saved"))).toBeTruthy();
});

it("reports a failed refresh while the last good list stays in effect", async () => {
  vi.mocked(api.dnsBlocklistSettings).mockResolvedValue(settings({
    policy: { enabled: true, sources: [light.url] },
    status: { active: true, domain_count: 1200, updated_at_unix: 1_790_000_000, failure: "download" },
  }));
  render(<DnsBlocklistSettings profile={{ id: "fixture" }} connected canManage />);
  expect(await screen.findByText(t("dns.blocklist.failure.download"))).toBeTruthy();
  expect((screen.getByRole("checkbox", { name: light.name }) as HTMLInputElement).checked).toBe(true);
});

it("asks for a repair when the server lacks the blocklist task", async () => {
  vi.mocked(api.serverConfiguration).mockResolvedValue({});
  render(<DnsBlocklistSettings profile={{ id: "fixture" }} connected canManage />);
  expect(await screen.findByText(t("dns.blocklist.unsupported"))).toBeTruthy();
  expect(api.dnsBlocklistSettings).not.toHaveBeenCalled();
});
