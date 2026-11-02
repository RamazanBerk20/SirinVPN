import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { RenameDeviceDialog } from "./RenameDeviceDialog";
import { t } from "../../i18n";

afterEach(cleanup);
const field = () => screen.getByRole("textbox") as HTMLInputElement;
const save = () => screen.getByRole("button", { name: t("devices.rename.save") }) as HTMLButtonElement;

it("validates the new name in place and keeps Rename off until it is valid and different", () => {
  render(<RenameDeviceDialog device={{ id: "phone", name: "Phone" }} onRename={vi.fn()} onClose={vi.fn()} />);
  expect(field().value).toBe("Phone");
  expect(save().disabled).toBe(true);
  fireEvent.change(field(), { target: { value: "   " } });
  expect(screen.getByText(t("devices.rename.empty"))).toBeTruthy();
  expect(field().getAttribute("aria-invalid")).toBe("true");
  expect(save().disabled).toBe(true);
  fireEvent.change(field(), { target: { value: "x".repeat(65) } });
  expect(screen.getByText(t("devices.rename.tooLong", { count: 64 }))).toBeTruthy();
  fireEvent.change(field(), { target: { value: "Work phone" } });
  expect(save().disabled).toBe(false);
});

it("closes after a rename and keeps the dialog open with the server's reason", async () => {
  const onClose = vi.fn();
  const onRename = vi.fn().mockRejectedValueOnce(new Error("Couldn’t rename the device. Name taken.")).mockResolvedValue(undefined);
  render(<RenameDeviceDialog device={{ id: "phone", name: "Phone" }} onRename={onRename} onClose={onClose} />);
  fireEvent.change(field(), { target: { value: "  Work phone " } });
  fireEvent.click(save());
  expect((await screen.findByRole("alert")).textContent).toContain("Name taken.");
  expect(onClose).not.toHaveBeenCalled();
  fireEvent.click(save());
  await waitFor(() => expect(onClose).toHaveBeenCalled());
  expect(onRename).toHaveBeenLastCalledWith("phone", "Work phone");
});
