import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { invoke } from "../platform";
import { SecretTextarea } from "./SecretInput";

vi.mock("../platform", () => ({ isAndroid: true, invoke: vi.fn() }));

it("shows native scan denial and passes only an opaque successful result to the form", async () => {
  const change = vi.fn();
  vi.mocked(invoke).mockRejectedValueOnce(new Error("Camera permission was not granted. You can enter the code securely instead."));
  render(<SecretTextarea aria-label="Invitation" onChange={change} />);
  fireEvent.click(screen.getByRole("button", { name: "Scan QR code" }));
  expect((await screen.findByRole("alert")).textContent).toContain("enter the code securely instead");
  expect(change).not.toHaveBeenCalled();
  vi.mocked(invoke).mockResolvedValueOnce("native-secret:fixture-reference");
  fireEvent.click(screen.getByRole("button", { name: "Scan QR code" }));
  await waitFor(() => expect(change).toHaveBeenCalledOnce());
  expect(change.mock.calls[0][0].target.value).toBe("native-secret:fixture-reference");
  expect(screen.queryByRole("alert")).toBeNull();
});
