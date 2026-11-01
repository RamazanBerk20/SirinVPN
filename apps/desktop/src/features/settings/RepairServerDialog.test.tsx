import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import type { ServerProfile, RepairResult } from "../../types";
import { RepairServerDialog } from "./RepairServerDialog";
import { t } from "../../i18n";

vi.mock("../../api", () => ({
  api: {
    getSshLogin: vi.fn(),
    saveSshLogin: vi.fn(),
    forgetSshLogin: vi.fn(),
    inspectSshHost: vi.fn(),
    trustSshHost: vi.fn(),
    repairServer: vi.fn(),
  },
}));
const fingerprint = `SHA256:${"A".repeat(43)}`;
const profile = {
  id: "a",
  name: "My VPS",
  endpoint: { host: "vps.example" },
  role: "owner",
} as ServerProfile;
const repaired = {
  dns_upstream: { mode: "recursive" },
  private_dns_records: [],
  artifact_sha256: "artifact",
} as unknown as RepairResult;

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.getSshLogin).mockResolvedValue(null);
  vi.mocked(api.saveSshLogin).mockResolvedValue({
    username: "root",
    ssh_port: 22,
    authentication: "agent",
    private_key_path: null,
  });
  vi.mocked(api.inspectSshHost).mockResolvedValue({
    fingerprint,
    status: "trusted",
  });
  vi.mocked(api.trustSshHost).mockResolvedValue(undefined);
  vi.mocked(api.repairServer).mockResolvedValue(repaired);
});
afterEach(cleanup);

it("reviews DNS scope on a trusted host and preserves transport at the command boundary", async () => {
  render(<RepairServerDialog profile={profile} open onOpenChange={vi.fn()} disconnected intent="dns" onCompleted={vi.fn().mockResolvedValue(undefined)} />);
  const agent = await screen.findByRole("button", { name: t("ssh.auth.agent") });
  await waitFor(() => expect(agent.matches(":disabled")).toBe(false));
  fireEvent.click(agent);
  fireEvent.click(screen.getByRole("button", { name: t("dns.resolver.mode.recursive") }));
  fireEvent.click(screen.getByRole("button", { name: t("vps.repair.action.review") }));
  await screen.findByRole("region", { name: t("dns.review.label") });
  expect(api.repairServer).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: t("vps.repair.action.apply") }));
  await screen.findByText(t("vps.repair.titleDoneDns"));
  expect(api.repairServer).toHaveBeenCalledWith(expect.objectContaining({ transport: null, dns_upstream: { mode: "recursive" }, private_dns_records: null, host_key_sha256: fingerprint }));
  expect(vi.mocked(api.repairServer).mock.calls[0][0]).not.toHaveProperty("nat64_prefix");
});

it("keeps the VPS's NAT64 choice unless the Owner sets or turns it off", async () => {
  const repairWith = async (choose: (group: HTMLElement) => void) => {
    vi.mocked(api.repairServer).mockClear();
    render(<RepairServerDialog profile={profile} open onOpenChange={vi.fn()} disconnected onCompleted={vi.fn().mockResolvedValue(undefined)} />);
    const agent = await screen.findByRole("button", { name: t("ssh.auth.agent") });
    await waitFor(() => expect(agent.matches(":disabled")).toBe(false));
    fireEvent.click(agent);
    choose(screen.getByRole("group", { name: t("dns.nat64.legend") }));
    fireEvent.click(screen.getByRole("button", { name: t("vps.repair.action.repair") }));
    await screen.findByText(t("vps.repair.titleDone"));
    const input = vi.mocked(api.repairServer).mock.calls[0][0];
    cleanup();
    return input;
  };
  expect(await repairWith(() => undefined)).not.toHaveProperty("nat64_prefix");
  expect(await repairWith((group) => fireEvent.click(within(group).getByRole("button", { name: t("dns.nat64.mode.clear") }))))
    .toHaveProperty("nat64_prefix", null);
  expect(await repairWith((group) => {
    fireEvent.click(within(group).getByRole("button", { name: t("dns.nat64.mode.replace") }));
    fireEvent.change(within(group).getByRole("textbox"), { target: { value: "64:ff9b::/96" } });
  })).toHaveProperty("nat64_prefix", "64:ff9b::/96");
});

async function setup() {
  render(
    <RepairServerDialog
      profile={profile}
      open
      onOpenChange={vi.fn()}
      disconnected
      onCompleted={vi.fn().mockResolvedValue(undefined)}
    />,
  );
  const agent = await screen.findByRole("button", { name: t("ssh.auth.agent") });
  await waitFor(() => expect(agent.matches(":disabled")).toBe(false));
  fireEvent.click(agent);
  fireEvent.click(screen.getByRole("button", { name: t("vps.repair.action.repair") }));
}

it("repairs an already trusted VPS directly with the inspected pin", async () => {
  await setup();
  await screen.findByText(t("vps.repair.titleDone"));
  expect(api.inspectSshHost).toHaveBeenCalledWith("vps.example", 22);
  expect(api.repairServer).toHaveBeenCalledWith(
    expect.objectContaining({ host_key_sha256: fingerprint, confirmed: true }),
  );
  expect(api.trustSshHost).not.toHaveBeenCalled();
  expect(screen.queryByRole("checkbox", { name: new RegExp(t("ssh.verify.confirm")) })).toBeNull();
});

for (const status of ["unknown", "changed"] as const) {
  it(`requires explicit verification for a ${status} key and remembers it before repairing`, async () => {
    vi.mocked(api.inspectSshHost).mockResolvedValue({ fingerprint, status });
    await setup();
    await screen.findByText(
      status === "changed"
        ? t("ssh.verify.titleChanged")
        : t("ssh.verify.title"),
    );
    expect(api.repairServer).not.toHaveBeenCalled();
    expect(api.trustSshHost).not.toHaveBeenCalled();
    expect(
      (screen.getByRole("button", { name: t("vps.repair.action.repair") }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: new RegExp(status === "changed" ? t("ssh.verify.confirmChanged") : t("ssh.verify.confirm")) }));
    fireEvent.click(screen.getByRole("button", { name: t("vps.repair.action.repair") }));
    await screen.findByText(t("vps.repair.titleDone"));
    expect(api.trustSshHost).toHaveBeenCalledWith(
      "vps.example",
      22,
      fingerprint,
    );
    expect(
      vi.mocked(api.trustSshHost).mock.invocationCallOrder[0],
    ).toBeLessThan(vi.mocked(api.repairServer).mock.invocationCallOrder[0]);
  });
}

it("does not perform the VPS action if the key changes during confirmation or cannot be saved", async () => {
  vi.mocked(api.inspectSshHost).mockResolvedValue({
    fingerprint,
    status: "unknown",
  });
  vi.mocked(api.trustSshHost).mockRejectedValue(
    new Error("The SSH key changed during verification."),
  );
  await setup();
  fireEvent.click(await screen.findByRole("checkbox", { name: new RegExp(t("ssh.verify.confirm")) }));
  fireEvent.click(screen.getByRole("button", { name: t("vps.repair.action.repair") }));
  await screen.findByText("The SSH key changed during verification.", { exact: false });
  expect(api.repairServer).not.toHaveBeenCalled();
});

it("reuses trust after an authentication failure instead of asking for the fingerprint again", async () => {
  vi.mocked(api.inspectSshHost).mockResolvedValueOnce({
    fingerprint,
    status: "unknown",
  });
  vi.mocked(api.repairServer).mockRejectedValueOnce(
    new Error("SSH authentication failed."),
  );
  await setup();
  fireEvent.click(await screen.findByRole("checkbox", { name: new RegExp(t("ssh.verify.confirm")) }));
  fireEvent.click(screen.getByRole("button", { name: t("vps.repair.action.repair") }));
  await screen.findByText("SSH authentication failed.", { exact: false });
  fireEvent.click(screen.getByRole("button", { name: t("vps.repair.action.repair") }));
  await screen.findByText(t("vps.repair.titleDone"));
  expect(api.trustSshHost).toHaveBeenCalledTimes(1);
  expect(api.repairServer).toHaveBeenCalledTimes(2);
});

it("ignores an inspection from a dialog closed by its parent", async () => {
  let resolve!: (value: { fingerprint: string; status: "trusted" }) => void;
  vi.mocked(api.inspectSshHost).mockImplementation(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  const props = {
    profile,
    onOpenChange: vi.fn(),
    disconnected: true,
    onCompleted: vi.fn().mockResolvedValue(undefined),
  };
  const { rerender } = render(<RepairServerDialog {...props} open />);
  const agent = await screen.findByRole("button", { name: t("ssh.auth.agent") });
  await waitFor(() => expect(agent.matches(":disabled")).toBe(false));
  fireEvent.click(agent);
  fireEvent.click(screen.getByRole("button", { name: t("vps.repair.action.repair") }));
  await waitFor(() => expect(api.inspectSshHost).toHaveBeenCalled());
  rerender(<RepairServerDialog {...props} open={false} />);
  await act(async () => resolve({ fingerprint, status: "trusted" }));
  expect(api.repairServer).not.toHaveBeenCalled();
});

it("does not start maintenance after unmounting during key confirmation", async () => {
  vi.mocked(api.inspectSshHost).mockResolvedValue({
    fingerprint,
    status: "unknown",
  });
  let resolve!: () => void;
  vi.mocked(api.trustSshHost).mockImplementation(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  await setup();
  fireEvent.click(await screen.findByRole("checkbox", { name: new RegExp(t("ssh.verify.confirm")) }));
  fireEvent.click(screen.getByRole("button", { name: t("vps.repair.action.repair") }));
  await waitFor(() => expect(api.trustSshHost).toHaveBeenCalled());
  cleanup();
  await act(async () => resolve());
  expect(api.repairServer).not.toHaveBeenCalled();
});

it("rebuilds the transport draft from the profile saved when the dialog reopens", async () => {
  const props = { onOpenChange: vi.fn(), disconnected: true, onCompleted: vi.fn().mockResolvedValue(undefined) };
  const { rerender } = render(<RepairServerDialog {...props} profile={profile} open={false} />);
  const restored = { ...profile, endpoint: { ...profile.endpoint, host: "restored.example", wireguard_port: 51900 } } as ServerProfile;
  rerender(<RepairServerDialog {...props} profile={restored} open />);
  expect((await screen.findByLabelText(t("ssh.transport.publicHost")) as HTMLInputElement).value).toBe("restored.example");
  expect((screen.getByLabelText(t("ssh.transport.directPort")) as HTMLInputElement).value).toBe("51900");
});
