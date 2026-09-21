import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import type { ServerProfile } from "../../types";
import { EndpointUpdateDialog } from "./EndpointUpdateDialog";

vi.mock("../../api", () => ({ api: {
  applyEndpointUpdate: vi.fn(),
  publishEndpointUpdate: vi.fn(),
  disconnect: vi.fn(),
  connect: vi.fn(),
} }));
beforeEach(() => vi.resetAllMocks());
afterEach(cleanup);
const profile = { id: "saved-server", role: "member", endpoint: { host: "old.example", wireguard_port: 51820 } } as ServerProfile;

it("hands an active endpoint update to the policy-preserving native operation", async () => {
  vi.mocked(api.applyEndpointUpdate).mockResolvedValue({} as never);
  const completed = vi.fn().mockResolvedValue(undefined);
  render(<EndpointUpdateDialog profile={profile} open connected onOpenChange={vi.fn()} onCompleted={completed} />);
  fireEvent.change(screen.getByRole("textbox"), { target: { value: "  sirm1.signed-checkpoint  " } });
  fireEvent.click(screen.getByRole("button", { name: "Verify and switch" }));
  await screen.findByText("Endpoint updated");
  expect(api.applyEndpointUpdate).toHaveBeenCalledWith(profile.id, "sirm1.signed-checkpoint");
  expect(completed).toHaveBeenCalledOnce();
  expect(api.disconnect).not.toHaveBeenCalled();
  expect(api.connect).not.toHaveBeenCalled();
});

it("retains the session and code when checkpoint verification fails", async () => {
  vi.mocked(api.applyEndpointUpdate).mockRejectedValue(new Error("The signed checkpoint is invalid."));
  const completed = vi.fn();
  render(<EndpointUpdateDialog profile={profile} open connected onOpenChange={vi.fn()} onCompleted={completed} />);
  fireEvent.change(screen.getByRole("textbox"), { target: { value: "sirm1.invalid" } });
  fireEvent.click(screen.getByRole("button", { name: "Verify and switch" }));
  await screen.findByText("The signed checkpoint is invalid.");
  await waitFor(() => expect((screen.getByRole("button", { name: "Verify and switch" }) as HTMLButtonElement).disabled).toBe(false));
  expect((screen.getByRole("textbox") as HTMLTextAreaElement).value).toBe("sirm1.invalid");
  expect(completed).not.toHaveBeenCalled();
  expect(api.disconnect).not.toHaveBeenCalled();
  expect(api.connect).not.toHaveBeenCalled();
});
