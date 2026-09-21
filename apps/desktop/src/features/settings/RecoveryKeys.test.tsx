import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { RecoveryKeys } from "./RecoveryKeys";
import { api } from "../../api";
import { save } from "@tauri-apps/plugin-dialog";
vi.mock("../../api", () => ({ api: { serverConfiguration: vi.fn(), membership: vi.fn(), recoverySettings: vi.fn(), createRecoveryKey: vi.fn(), exportRecoveryPackage: vi.fn() } }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ save: vi.fn() }));
const key = { key: "sirk1.fixture-only", qr_svg: '<svg viewBox="0 0 29 29"></svg>', recovery_id: "recovery-fixture" };
beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(window, "confirm").mockReturnValue(false);
  vi.mocked(api.serverConfiguration).mockResolvedValue({ recovery_keys_enabled: true });
  vi.mocked(api.membership).mockResolvedValue({ members: [], active_invitations: [] });
  vi.mocked(api.recoverySettings).mockResolvedValue({ key: null, can_issue_key: true, enrollment_finishing: false, policy: { administrator_member_ids: [] } });
  vi.mocked(api.createRecoveryKey).mockImplementation(async () => {
    vi.mocked(api.recoverySettings).mockResolvedValue({ key: { recovery_id: key.recovery_id, identity_fingerprint: "fixture" }, can_issue_key: true, enrollment_finishing: false, policy: { administrator_member_ids: [] } });
    return key;
  });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
async function issue() {
  render(<><RecoveryKeys profile={{ id: "fixture" }} connected owner /><button onClick={() => { window.location.hash = "elsewhere"; }}>Leave recovery</button></>);
  fireEvent.click(await screen.findByRole("checkbox", { name: /anyone holding this key/ }));
  fireEvent.click(screen.getByRole("button", { name: "Create recovery key" }));
  await screen.findByDisplayValue(key.key);
}
it("does not mark cancelled or failed file saving as retained recovery material", async () => {
  await issue();
  fireEvent.change(screen.getByLabelText(/^Recovery package password/), { target: { value: "fictional-password" } });
  fireEvent.change(screen.getByLabelText("Repeat package password"), { target: { value: "fictional-password" } });
  vi.mocked(save).mockResolvedValueOnce(null);
  fireEvent.click(screen.getByRole("button", { name: "Save encrypted recovery package" }));
  await waitFor(() => expect(save).toHaveBeenCalledOnce());
  expect(api.exportRecoveryPackage).not.toHaveBeenCalled();
  expect((screen.getByRole("button", { name: "Finish recovery setup" }) as HTMLButtonElement).disabled).toBe(true);
  vi.mocked(save).mockResolvedValueOnce("fixture.sirrec");
  vi.mocked(api.exportRecoveryPackage).mockRejectedValueOnce(new Error("Storage permission denied"));
  fireEvent.click(screen.getByRole("button", { name: "Save encrypted recovery package" }));
  expect(await screen.findByText("Storage permission denied")).toBeTruthy();
  expect(screen.queryByText(/Encrypted recovery package saved/)).toBeNull();
});
it("guards abandonment and clears the displayed secret only after explicit completion", async () => {
  await issue();
  fireEvent.click(screen.getByRole("button", { name: "Leave recovery" }));
  expect(window.confirm).toHaveBeenCalled();
  expect(screen.getByDisplayValue(key.key)).toBeTruthy();
  fireEvent.click(screen.getByRole("checkbox", { name: /I have saved this recovery key/ }));
  fireEvent.click(screen.getByRole("button", { name: "Finish recovery setup" }));
  expect(screen.queryByDisplayValue(key.key)).toBeNull();
  expect(screen.getByText(/Recovery material acknowledged/)).toBeTruthy();
});
it("does not lose an issued key when the VPN connection drops", async () => {
  const view = render(<RecoveryKeys profile={{ id: "fixture" }} connected owner />);
  fireEvent.click(await screen.findByRole("checkbox", { name: /anyone holding this key/ }));
  fireEvent.click(screen.getByRole("button", { name: "Create recovery key" }));
  await screen.findByDisplayValue(key.key);
  view.rerender(<RecoveryKeys profile={{ id: "fixture" }} connected={false} owner />);
  expect(screen.getByDisplayValue(key.key)).toBeTruthy();
  expect((screen.getByRole("button", { name: "Finish recovery setup" }) as HTMLButtonElement).disabled).toBe(true);
});
it("ignores recovery material issued for a profile that is no longer displayed", async () => {
  let finish!: (value: typeof key) => void;
  vi.mocked(api.createRecoveryKey).mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const view = render(<RecoveryKeys profile={{ id: "first" }} connected owner />);
  fireEvent.click(await screen.findByRole("checkbox", { name: /anyone holding this key/ }));
  fireEvent.click(screen.getByRole("button", { name: "Create recovery key" }));
  await waitFor(() => expect(api.createRecoveryKey).toHaveBeenCalledOnce());
  view.rerender(<RecoveryKeys profile={{ id: "second" }} connected owner />);
  await act(async () => finish(key));
  expect(screen.queryByDisplayValue(key.key)).toBeNull();
  expect(screen.queryByRole("button", { name: "Copy recovery key" })).toBeNull();
});
