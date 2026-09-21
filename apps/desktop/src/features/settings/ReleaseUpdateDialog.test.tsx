import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ReleaseUpdateDialog } from "./ReleaseUpdateDialog";
import { ReleaseUpdateSession } from "./ReleaseUpdateSession";
import { api } from "../../api";
import type { ReleaseUpdateCandidate } from "../../types";

vi.mock("../../api", () => ({ api: {
  checkReleaseUpdate: vi.fn(), installReleaseUpdate: vi.fn(), discardReleaseUpdate: vi.fn(),
  releaseUpdateStatus: vi.fn(), rollbackReleaseUpdate: vi.fn(),
} }));
const candidate: ReleaseUpdateCandidate = {
  current_version: "0.1.0", release_version: "0.2.0", release_sequence: "2", channel: "stable",
  security_update: false, trust_policy_sequence: "1", root_key_id_sha256: "a".repeat(64), release_key_id_sha256: "b".repeat(64),
  artifact_file_name: "SirinVPN_0.2.0.AppImage", artifact_target: "x86_64-unknown-linux-gnu",
  artifact_sha256: "c".repeat(64), artifact_size_bytes: 4096, newer_than_running: true, debian_install_available: false,
  installer_kind: "appimage", appimage_install_available: true,
};
async function check() {
  fireEvent.change(screen.getByLabelText(/^Release source/), { target: { value: ["https", "://release.example/stable/"].join("") } });
  fireEvent.click(screen.getByRole("button", { name: "Check and verify release" }));
  await screen.findByText("Root-authenticated");
}
describe("portable app updates", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.releaseUpdateStatus).mockResolvedValue({ installer_kind: "appimage", baseline_required: false, rollback_version: null });
    vi.mocked(api.checkReleaseUpdate).mockResolvedValue(candidate);
    vi.mocked(api.installReleaseUpdate).mockResolvedValue(candidate);
  });
  afterEach(cleanup);
  it("allows confirmed AppImage replacement while the service is connected", async () => {
    render(<ReleaseUpdateDialog open onOpenChange={vi.fn()} installationReady={false} />);
    await check();
    const button = screen.getByRole("button", { name: "Install authenticated update" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: /exact authenticated AppImage/ }));
    fireEvent.click(button);
    await waitFor(() => expect(api.installReleaseUpdate).toHaveBeenCalledWith(true));
    expect(await screen.findByText(/Close and reopen the same AppImage/)).toBeTruthy();
  });
  it("binds the same-version signed baseline only after its own confirmation", async () => {
    vi.mocked(api.checkReleaseUpdate).mockResolvedValue({ ...candidate, release_version: "0.1.0", newer_than_running: false, baseline_bind_available: true });
    vi.mocked(api.installReleaseUpdate).mockResolvedValue({ ...candidate, release_version: "0.1.0", baseline_bound: true });
    render(<ReleaseUpdateDialog open onOpenChange={vi.fn()} installationReady={false} />);
    await check();
    expect(api.installReleaseUpdate).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("checkbox", { name: /verification of this installed package/ }));
    fireEvent.click(screen.getByRole("button", { name: "Verify installed release" }));
    expect(await screen.findByText("Signed baseline verified")).toBeTruthy();
  });
  it("retains the authenticated candidate across prerequisite navigation and requires fresh consent", async () => {
    vi.mocked(api.checkReleaseUpdate).mockResolvedValue({ ...candidate, installer_kind: "debian", appimage_install_available: false, debian_install_available: true });
    const review = vi.fn();
    const page = (visible: boolean, ready: boolean) => <ReleaseUpdateSession>{visible
      ? <ReleaseUpdateDialog open onOpenChange={vi.fn()} onReviewPrerequisites={review} installationReady={ready} />
      : <p>Connection controls</p>}</ReleaseUpdateSession>;
    const view = render(page(true, false));
    await check();
    fireEvent.click(screen.getByRole("button", { name: "Review connection prerequisites" }));
    expect(review).toHaveBeenCalledOnce();
    view.rerender(page(false, false));
    expect(api.discardReleaseUpdate).not.toHaveBeenCalled();
    view.rerender(page(true, true));
    expect(await screen.findByText("Root-authenticated")).toBeTruthy();
    expect(api.checkReleaseUpdate).toHaveBeenCalledOnce();
    const install = screen.getByRole("button", { name: "Install authenticated update" });
    expect(install.matches(":disabled")).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: /exact authenticated Debian package/ }));
    fireEvent.click(install);
    await waitFor(() => expect(api.installReleaseUpdate).toHaveBeenCalledWith(true));
  });
  it("confirms the displayed retained version and locks the dialog during rollback", async () => {
    vi.mocked(api.releaseUpdateStatus).mockResolvedValue({ installer_kind: "appimage", baseline_required: false, rollback_version: "0.1.0" });
    let complete!: () => void;
    vi.mocked(api.rollbackReleaseUpdate).mockReturnValue(new Promise<void>((done) => { complete = done; }));
    render(<ReleaseUpdateDialog open onOpenChange={vi.fn()} installationReady />);
    const confirmation = await screen.findByRole("checkbox", { name: /Restore AppImage 0.1.0/ });
    fireEvent.click(confirmation);
    fireEvent.click(screen.getByRole("button", { name: "Restore previous AppImage" }));
    await waitFor(() => expect(api.rollbackReleaseUpdate).toHaveBeenCalledWith("0.1.0"));
    expect(screen.getByRole("button", { name: "Close app updates" }).matches(":disabled")).toBe(true);
    expect((screen.getByRole("button", { name: "Check and verify release" }) as HTMLButtonElement).disabled).toBe(true);
    complete();
    expect(await screen.findByText(/AppImage 0.1.0 restored/)).toBeTruthy();
  });
});
