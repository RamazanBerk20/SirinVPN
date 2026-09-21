import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import type { ServerProfile, RepairResult } from "../../types";
import { RepairServerDialog } from "./RepairServerDialog";

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
  const agent = await screen.findByRole("button", { name: "SSH agent" });
  await waitFor(() => expect(agent.matches(":disabled")).toBe(false));
  fireEvent.click(agent);
  fireEvent.click(screen.getByRole("button", { name: "Recursive" }));
  fireEvent.click(screen.getByRole("button", { name: "Review DNS changes" }));
  await screen.findByRole("region", { name: "DNS change review" });
  expect(api.repairServer).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Apply DNS configuration" }));
  await screen.findByText("DNS configuration complete");
  expect(api.repairServer).toHaveBeenCalledWith(expect.objectContaining({ transport: null, dns_upstream: { mode: "recursive" }, private_dns_records: null, host_key_sha256: fingerprint }));
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
  const agent = await screen.findByRole("button", { name: "SSH agent" });
  await waitFor(() => expect(agent.matches(":disabled")).toBe(false));
  fireEvent.click(agent);
  fireEvent.click(screen.getByRole("button", { name: "Repair VPS" }));
}

it("repairs an already trusted VPS directly with the inspected pin", async () => {
  await setup();
  await screen.findByText("Repair complete");
  expect(api.inspectSshHost).toHaveBeenCalledWith("vps.example", 22);
  expect(api.repairServer).toHaveBeenCalledWith(
    expect.objectContaining({ host_key_sha256: fingerprint, confirmed: true }),
  );
  expect(api.trustSshHost).not.toHaveBeenCalled();
  expect(screen.queryByRole("checkbox", { name: /fingerprint/ })).toBeNull();
});

for (const status of ["unknown", "changed"] as const) {
  it(`requires explicit verification for a ${status} key and remembers it before repairing`, async () => {
    vi.mocked(api.inspectSshHost).mockResolvedValue({ fingerprint, status });
    await setup();
    await screen.findByText(
      status === "changed"
        ? "The VPS SSH key has changed"
        : "Verify this VPS once",
    );
    expect(api.repairServer).not.toHaveBeenCalled();
    expect(api.trustSshHost).not.toHaveBeenCalled();
    expect(
      (screen.getByRole("button", { name: "Repair VPS" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: /I verified/ }));
    fireEvent.click(screen.getByRole("button", { name: "Repair VPS" }));
    await screen.findByText("Repair complete");
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
  fireEvent.click(await screen.findByRole("checkbox", { name: /I verified/ }));
  fireEvent.click(screen.getByRole("button", { name: "Repair VPS" }));
  await screen.findByText("The SSH key changed during verification.");
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
  fireEvent.click(await screen.findByRole("checkbox", { name: /I verified/ }));
  fireEvent.click(screen.getByRole("button", { name: "Repair VPS" }));
  await screen.findByText("SSH authentication failed.");
  fireEvent.click(screen.getByRole("button", { name: "Repair VPS" }));
  await screen.findByText("Repair complete");
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
  const agent = await screen.findByRole("button", { name: "SSH agent" });
  await waitFor(() => expect(agent.matches(":disabled")).toBe(false));
  fireEvent.click(agent);
  fireEvent.click(screen.getByRole("button", { name: "Repair VPS" }));
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
  fireEvent.click(await screen.findByRole("checkbox", { name: /I verified/ }));
  fireEvent.click(screen.getByRole("button", { name: "Repair VPS" }));
  await waitFor(() => expect(api.trustSshHost).toHaveBeenCalled());
  cleanup();
  await act(async () => resolve());
  expect(api.repairServer).not.toHaveBeenCalled();
});
