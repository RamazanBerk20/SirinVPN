import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import { LocalComponentUpdate } from "./LocalComponentUpdate";

vi.mock("../../api", () => ({ api: { localComponentUpdateStatus: vi.fn(), installLocalVpnComponent: vi.fn() } }));
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.localComponentUpdateStatus).mockResolvedValue({ install_available: true, update_required: true });
});
afterEach(cleanup);

it("reviews the bundled helper without installing and refreshes only after explicit installation succeeds", async () => {
  const updated = vi.fn().mockResolvedValue(undefined);
  const releaseUpdate = vi.fn();
  render(<LocalComponentUpdate open disconnected onOpenChange={vi.fn()} onCheckUpdates={releaseUpdate} onUpdated={updated} />);
  const button = await screen.findByRole("button", { name: "Update local VPN component" });
  expect(api.installLocalVpnComponent).not.toHaveBeenCalled();
  expect(screen.queryByRole("alert")).toBeNull();
  fireEvent.click(button);
  await screen.findByText("The local VPN component is updated. You can connect from Home.");
  expect(api.installLocalVpnComponent).toHaveBeenCalledOnce();
  expect(releaseUpdate).not.toHaveBeenCalled();
  await waitFor(() => expect(updated).toHaveBeenCalledOnce());
});

it("retains the update action after administrator authorization is cancelled", async () => {
  vi.mocked(api.installLocalVpnComponent).mockRejectedValue(new Error("Administrator authorization was cancelled."));
  const updated = vi.fn();
  render(<LocalComponentUpdate open disconnected onOpenChange={vi.fn()} onCheckUpdates={vi.fn()} onUpdated={updated} />);
  fireEvent.click(await screen.findByRole("button", { name: "Update local VPN component" }));
  expect((await screen.findByRole("alert")).textContent).toContain("Administrator authorization was cancelled.");
  expect(updated).not.toHaveBeenCalled();
  expect(screen.queryByText("The local VPN component is updated. You can connect from Home.")).toBeNull();
  expect((screen.getByRole("button", { name: "Update local VPN component" }) as HTMLButtonElement).disabled).toBe(false);
});

it("does not replace the component while a VPN session or protection is retained", async () => {
  render(<LocalComponentUpdate open disconnected={false} onOpenChange={vi.fn()} onCheckUpdates={vi.fn()} onUpdated={vi.fn()} />);
  const button = await screen.findByRole("button", { name: "Update local VPN component" });
  expect((button as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(button);
  expect(api.installLocalVpnComponent).not.toHaveBeenCalled();
});
