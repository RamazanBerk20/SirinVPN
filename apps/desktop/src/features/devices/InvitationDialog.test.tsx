import { invoke } from "@tauri-apps/api/core";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { InvitationDialog } from "./InvitationDialog";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn(), Channel: vi.fn() }));
vi.mock("./InvitationShare", () => ({ InvitationShare: () => <div>Invitation to share</div> }));

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(invoke).mockResolvedValue({
    invitation_id: "invitation", expires_at_unix: 4102444800,
    code: "synthetic-test-code", qr_svg: "",
  });
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

const props = {
  profile: { id: "server" }, open: true, target: null,
  canCreateAdmin: true, recipientNamesAvailable: true,
  onRefreshConfiguration: vi.fn().mockResolvedValue(undefined),
  onOpenChange: vi.fn(), onCreated: vi.fn().mockResolvedValue(undefined),
};
const createButton = () => screen.getByRole("button", { name: /Create .* code/ }) as HTMLButtonElement;

it("creates recipient-named invitations without asking the inviter for names on an updated VPS", async () => {
  render(<InvitationDialog {...props} />);
  expect(screen.queryByLabelText(/Member display name/)).toBeNull();
  expect(screen.queryByLabelText("Device name")).toBeNull();
  fireEvent.change(screen.getByLabelText(/Access level/), { target: { value: "admin" } });
  fireEvent.click(createButton());
  await screen.findByText("Invitation to share");
  expect(screen.getByText(/Copy or share this code before closing/)).toBeTruthy();
  expect(invoke).toHaveBeenCalledWith("create_invitation", { input: expect.objectContaining({
    server_id: "server", recipient_names: true, member_name: "", device_name: "",
    administrator: true, max_uses: 1, target_member_id: null,
  }) });
});

it("confirms copying only after clipboard access succeeds and explains failures", async () => {
  const writeText = vi.fn().mockRejectedValueOnce(new Error("Clipboard unavailable"));
  vi.stubGlobal("navigator", { clipboard: { writeText } });
  render(<InvitationDialog {...props} />);
  fireEvent.click(createButton());
  await screen.findByText("Invitation to share");
  expect(writeText).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Copy code" }));
  await screen.findByText(/The code could not be copied/);
  expect(screen.queryByRole("button", { name: "Copied" })).toBeNull();
  writeText.mockResolvedValue(undefined);
  fireEvent.click(screen.getByRole("button", { name: "Copy code" }));
  await screen.findByRole("button", { name: "Copied" });
  expect(screen.queryByText(/The code could not be copied/)).toBeNull();
  expect(writeText).toHaveBeenLastCalledWith("synthetic-test-code");
});

it("keeps a newly created code visible through refresh failures and clears it when closed", async () => {
  const { rerender } = render(<InvitationDialog {...props} />);
  fireEvent.click(createButton());
  await screen.findByText("Invitation to share");
  rerender(<InvitationDialog {...props} recipientNamesAvailable={null} configurationError="Access unavailable" />);
  expect(screen.getByText("Invitation to share")).toBeTruthy();
  await waitFor(() => expect((screen.getByRole("button", { name: "Close" }) as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(screen.getByRole("button", { name: "Close" }));
  expect(props.onOpenChange).toHaveBeenCalledWith(false);
  rerender(<InvitationDialog {...props} open={false} />);
  rerender(<InvitationDialog {...props} />);
  expect(screen.queryByText("Invitation to share")).toBeNull();
  expect(createButton().disabled).toBe(false);
  expect(invoke).toHaveBeenCalledOnce();
});

it("uses assigned names and the compatible request format on an older VPS", async () => {
  render(<InvitationDialog {...props} recipientNamesAvailable={false} />);
  expect(screen.getByText(/earlier invitation format/)).toBeTruthy();
  expect(createButton().disabled).toBe(true);
  expect(screen.queryByLabelText(/Member display name/)).toBeNull();
  fireEvent.change(screen.getByLabelText("Device name"), { target: { value: "  Phone  " } });
  fireEvent.click(createButton());
  await screen.findByText("Invitation to share");
  expect(invoke).toHaveBeenCalledWith("create_invitation", { input: expect.objectContaining({
    recipient_names: false, member_name: "Phone", device_name: "Phone", target_member_id: null,
  }) });
});

it("preserves the existing member identity when adding a device on an older VPS", async () => {
  render(<InvitationDialog {...props} recipientNamesAvailable={false}
    target={{ id: "existing", name: "Existing member", role: "member", administrator: true, devices: [] }} />);
  expect(screen.queryByLabelText(/Member display name/)).toBeNull();
  fireEvent.change(screen.getByLabelText("Device name"), { target: { value: "Second phone" } });
  fireEvent.click(createButton());
  await screen.findByText("Invitation to share");
  expect(invoke).toHaveBeenCalledWith("create_invitation", { input: expect.objectContaining({
    recipient_names: false, member_name: "Existing member", device_name: "Second phone",
    target_member_id: "existing", administrator: true,
  }) });
});

it("waits for a confirmed capability and offers a retry after a server check fails", async () => {
  const retry = vi.fn().mockResolvedValue(undefined);
  const { rerender } = render(<InvitationDialog {...props} recipientNamesAvailable={null} onRefreshConfiguration={retry} />);
  expect(screen.getByText(/Checking invitation support/)).toBeTruthy();
  expect(createButton().disabled).toBe(true);
  fireEvent.submit(createButton().closest("form")!);
  expect(invoke).not.toHaveBeenCalled();
  rerender(<InvitationDialog {...props} recipientNamesAvailable={null} onRefreshConfiguration={retry} configurationError="VPS is unreachable." />);
  fireEvent.click(screen.getByRole("button", { name: "Retry server check" }));
  await waitFor(() => expect(retry).toHaveBeenCalledOnce());
  expect(createButton().disabled).toBe(true);
  expect(screen.queryByLabelText(/Member display name/)).toBeNull();
  rerender(<InvitationDialog {...props} recipientNamesAvailable={true} />);
  expect(createButton().disabled).toBe(false);
  expect(screen.queryByText(/earlier invitation format/)).toBeNull();
});
