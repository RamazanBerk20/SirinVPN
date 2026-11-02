import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import type { ServerProfile } from "../../types";
import { KeyRotationDialog } from "./KeyRotationDialog";
import { t } from "../../i18n";

vi.mock("../../api", () => ({ api: { rotateDeviceKeys: vi.fn() } }));
const profile = { id: "a", name: "My VPS", endpoint: { host: "vps.example" }, role: "owner" } as ServerProfile;
beforeEach(() => vi.resetAllMocks());
afterEach(cleanup);

it("keeps consent after a failed rotation, says the old keys still work and offers Try again", async () => {
  vi.mocked(api.rotateDeviceKeys).mockRejectedValueOnce(new Error("The server refused the new keys."));
  const props = { profile, open: true, onOpenChange: vi.fn(), onCompleted: vi.fn().mockResolvedValue(undefined), onPendingChanged: vi.fn().mockResolvedValue(undefined) };
  render(<KeyRotationDialog {...props} pending={false} />);
  expect(screen.getByText(t("vps.rotation.confirmFirst"))).toBeTruthy();
  fireEvent.click(screen.getByRole("checkbox", { name: new RegExp(t("settings.keyRotation.confirmation.accept")) }));
  fireEvent.click(screen.getByRole("button", { name: t("settings.keyRotation.confirmation.rotate") }));
  await screen.findByText("The server refused the new keys.", { exact: false });
  expect(screen.getByText(t("vps.rotation.unchanged"))).toBeTruthy();
  expect((screen.getByRole("checkbox") as HTMLInputElement).checked).toBe(true);
  vi.mocked(api.rotateDeviceKeys).mockResolvedValueOnce({ rotation_id: "r", server_id: "a", device_id: "d", identity_fingerprint: "f".repeat(64), resumed: false });
  fireEvent.click(screen.getByRole("button", { name: t("common.action.retry") }));
  await screen.findByText(t("settings.keyRotation.done.title"));
  expect(screen.getByText("f".repeat(64))).toBeTruthy();
});
