import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import type { ServerProfile } from "../../types";
import { EndpointUpdateDialog } from "./EndpointUpdateDialog";
import { t } from "../../i18n";

vi.mock("../../api", () => ({ api: {
  applyEndpointUpdate: vi.fn(),
  publishEndpointUpdate: vi.fn(),
  availableEndpointUpdate: vi.fn(),
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
  fireEvent.click(screen.getByRole("button", { name: t("vps.endpoint.verify") }));
  await screen.findByText(t("vps.endpoint.applied"));
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
  fireEvent.click(screen.getByRole("button", { name: t("vps.endpoint.verify") }));
  await screen.findByText("The signed checkpoint is invalid.");
  await waitFor(() => expect((screen.getByRole("button", { name: t("vps.endpoint.verify") }) as HTMLButtonElement).disabled).toBe(false));
  expect((screen.getByRole("textbox") as HTMLTextAreaElement).value).toBe("sirm1.invalid");
  expect(completed).not.toHaveBeenCalled();
  expect(api.disconnect).not.toHaveBeenCalled();
  expect(api.connect).not.toHaveBeenCalled();
});

it("ties the update summary to its own code and publishes the signed code from the share tab", async () => {
  const signed = { code: "sirm1.signed", generation: 2, previous_endpoint: { host: "old.example", wireguard_port: 51820 }, endpoint: { host: "new.example", wireguard_port: 51820 } };
  vi.mocked(api.availableEndpointUpdate).mockResolvedValue(signed as never);
  vi.mocked(api.publishEndpointUpdate).mockResolvedValue(undefined as never);
  const owner = { ...profile, role: "owner" } as ServerProfile;
  render(<EndpointUpdateDialog profile={owner} open connected onOpenChange={vi.fn()} onCompleted={vi.fn().mockResolvedValue(undefined)} />);
  fireEvent.click(screen.getByRole("button", { name: t("vps.endpoint.getFromServer") }));
  await screen.findByText("new.example:51820");
  fireEvent.change(screen.getByRole("textbox"), { target: { value: "sirm1.different" } });
  expect(screen.queryByText("new.example:51820")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: t("vps.endpoint.tab.share") }));
  expect((screen.getByLabelText(t("vps.endpoint.code")) as HTMLTextAreaElement).value).toBe("sirm1.signed");
  fireEvent.click(screen.getByRole("button", { name: t("vps.endpoint.publish") }));
  await waitFor(() => expect(api.publishEndpointUpdate).toHaveBeenCalledWith(owner.id, "sirm1.signed"));
});
