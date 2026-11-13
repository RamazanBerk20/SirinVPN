import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import { t } from "../../i18n";
import type { MembershipSnapshot } from "../../types";
import { DevicesPage } from "./DevicesPage";
import { forgetMembership } from "./membershipCache";
import { capabilities, codeTitle } from "./model";
import { couplingNote } from "./PersonPanel";

vi.mock("../../api", () => ({ api: { serverConfiguration: vi.fn(), membership: vi.fn(), renamePerson: vi.fn(), cancelInvitation: vi.fn(), createInvitation: vi.fn() } }));
afterEach(() => { cleanup(); vi.resetAllMocks(); forgetMembership(); });

const profile = { id: "server", name: "My VPS", device_id: "laptop" };
const alone: MembershipSnapshot = {
  members: [{ id: "me", name: "Deniz", role: "owner", devices: [{ id: "laptop", member_id: "me", name: "Laptop", client_tunnel_address: "10.77.0.2" }] }],
  active_invitations: [],
};
const configuration = { member_lifecycle_enabled: true, recipient_names_enabled: true, reusable_invitations_enabled: true };

function show(snapshot: MembershipSnapshot, accessLevel: "owner" | "admin" | "member" = "owner", connected = true, server: Record<string, boolean> = configuration) {
  vi.mocked(api.serverConfiguration).mockResolvedValue(server);
  vi.mocked(api.membership).mockResolvedValue(snapshot);
  render(<DevicesPage profile={profile} connected={connected} accessLevel={accessLevel} onAccessChanged={vi.fn()} />);
}

it("offers two explicit choices when this is the only device", async () => {
  show(alone);
  await waitFor(() => expect(screen.getByTestId("devices-page").dataset.state).toBe("ready"));
  expect(screen.getByTestId("my-devices").textContent).toContain(t("devices.page.mine"));
  expect(screen.getByTestId("empty-add-mine").textContent).toBe(t("devices.empty.mine"));
  expect(screen.getByTestId("empty-add-someone").textContent).toBe(t("devices.empty.someone"));
  expect(screen.getByText(t("devices.empty.body"))).toBeTruthy();
});

it("has no Add device button, only a reason, when the caller can add nothing", async () => {
  const member = { ...alone, members: [{ ...alone.members[0], role: "member" as const }] };
  show(member, "member");
  await waitFor(() => expect(screen.getByTestId("devices-page").dataset.state).toBe("ready"));
  expect(screen.queryByTestId("add-device")).toBeNull();
  expect(screen.getByTestId("add-device-reason").textContent).toBe(t("devices.page.cannotAdd"));
});

it("shows this device instead of a blank page while disconnected with nothing saved", () => {
  show(alone, "owner", false);
  expect(screen.getByTestId("devices-page").dataset.state).toBe("disconnected");
  expect(screen.getByText(t("devices.page.disconnected"))).toBeTruthy();
  expect(screen.getByText(t("common.noun.thisDevice"), { selector: ".this-device-chip" })).toBeTruthy();
  expect(api.membership).not.toHaveBeenCalled();
});

it("cancels the person's device join codes and retries a rename the server refused for them", async () => {
  const ayse = { id: "ayse", name: "Ayşe", role: "member" as const, devices: [] };
  const waiting = (id: string, extra = {}) => ({ id, member_name: "Ayşe", device_name: "", expires_at_unix: 2_000_000_000, ...extra });
  const snapshot: MembershipSnapshot = { members: [...alone.members, ayse],
    active_invitations: [waiting("for-ayse", { target_member_id: "ayse" }), waiting("by-ayse", { issued_by_member_id: "ayse" })] };
  vi.mocked(api.serverConfiguration).mockResolvedValue({ ...configuration, person_rename_enabled: true });
  vi.mocked(api.membership).mockResolvedValue(snapshot);
  vi.mocked(api.renamePerson)
    .mockRejectedValueOnce(Object.assign(new Error("cancel the codes first"), { code: "person_has_join_codes", params: {} }))
    .mockResolvedValueOnce({ ...snapshot, members: [alone.members[0], { ...ayse, name: "Ayşe Y" }], active_invitations: [] });
  vi.mocked(api.cancelInvitation).mockResolvedValue(undefined as never);
  render(<DevicesPage profile={profile} connected accessLevel="owner" onAccessChanged={vi.fn()} />);
  await waitFor(() => expect(screen.getByTestId("devices-page").dataset.state).toBe("ready"));
  fireEvent.click(screen.getAllByTestId("open-person").find((button) => button.textContent === "Ayşe")!);
  fireEvent.change(screen.getByDisplayValue("Ayşe"), { target: { value: "Ayşe Y" } });
  fireEvent.click(screen.getByTestId("rename-person"));
  const retry = await screen.findByTestId("cancel-codes-rename");
  expect(screen.getByText(t("devices.person.renameCodesWaiting", { count: 1, name: "Ayşe" }))).toBeTruthy();
  expect(screen.queryByRole("alert")).toBeNull();
  fireEvent.click(retry);
  await waitFor(() => expect(api.renamePerson).toHaveBeenCalledTimes(2));
  // Only the codes that bring a device for her block the rename.
  expect(api.cancelInvitation).toHaveBeenCalledTimes(1);
  expect(api.cancelInvitation).toHaveBeenCalledWith("server", "for-ayse");
  await waitFor(() => expect(screen.queryByTestId("cancel-codes-rename")).toBeNull());
});

it("shows a taken person name in the rename field, not as a join-code conflict", async () => {
  const ayse = { id: "ayse", name: "Ayşe", role: "member" as const, devices: [] };
  vi.mocked(api.serverConfiguration).mockResolvedValue({ ...configuration, person_rename_enabled: true });
  vi.mocked(api.membership).mockResolvedValue({ members: [...alone.members, ayse], active_invitations: [] });
  vi.mocked(api.renamePerson).mockRejectedValueOnce(Object.assign(new Error("person name already exists"), { code: "person_name_taken", params: {} }));
  render(<DevicesPage profile={profile} connected accessLevel="owner" onAccessChanged={vi.fn()} />);
  await waitFor(() => expect(screen.getByTestId("devices-page").dataset.state).toBe("ready"));
  fireEvent.click(screen.getAllByTestId("open-person").find((button) => button.textContent === "Ayşe")!);
  fireEvent.change(screen.getByDisplayValue("Ayşe"), { target: { value: "You" } });
  fireEvent.click(screen.getByTestId("rename-person"));
  expect(await screen.findByText(t("common.errorCode.person_name_taken"))).toBeTruthy();
  expect(screen.queryByTestId("cancel-codes-rename")).toBeNull();
});

it("counts codes a person created exactly when the server reports issuers, and only hints at them otherwise", () => {
  const admin = { id: "a", name: "Ayşe", role: "member" as const, administrator: true, devices: [] };
  const code = (id: string, extra = {}) => ({ id, member_name: "X", device_name: "", expires_at_unix: 2_000_000_000, ...extra });
  const snapshot = { members: [admin], active_invitations: [code("for", { target_member_id: "a", issued_by_member_id: "o" }), code("by", { issued_by_member_id: "a" }),
    code("both", { target_member_id: "a", issued_by_member_id: "a" }), code("other", { issued_by_member_id: "o" })] };
  const newer = capabilities({ ...configuration, named_join_codes_enabled: true }, false);
  const older = capabilities(configuration, false);
  expect(couplingNote(snapshot, admin, newer)).toEqual({ count: 3, mayHaveCreated: false });
  expect(couplingNote({ ...snapshot, active_invitations: [] }, admin, newer)).toEqual({ count: 0, mayHaveCreated: false });
  const legacy = { ...snapshot, active_invitations: [code("for", { target_member_id: "a" })] };
  expect(couplingNote(legacy, admin, older)).toEqual({ count: 1, mayHaveCreated: true });
});

async function addSomeoneNew(server: Record<string, boolean>) {
  show(alone, "owner", true, server);
  await waitFor(() => expect(screen.getByTestId("devices-page").dataset.state).toBe("ready"));
  vi.mocked(api.createInvitation).mockResolvedValue({ invitation_id: "c", expires_at_unix: 2_000_000_000, code: "sirin1.x", qr_svg: "<svg/>" });
  fireEvent.click(screen.getByTestId("empty-add-someone"));
  await screen.findByTestId("add-device-wizard");
}

it("asks the inviter for no name when someone new joins a current server, and sends no fixed name", async () => {
  await addSomeoneNew({ ...configuration, named_join_codes_enabled: true });
  expect(screen.queryByTestId("new-person-name")).toBeNull();
  fireEvent.click(screen.getByTestId("wizard-next"));
  expect(screen.queryByTestId("device-name")).toBeNull();
  fireEvent.click(screen.getByTestId("wizard-create"));
  await waitFor(() => expect(api.createInvitation).toHaveBeenCalled());
  const call = vi.mocked(api.createInvitation).mock.calls[0];
  expect(call[1]).toBe("");
  expect(call[2]).toBe("");
  expect(call).toHaveLength(9);
  expect(call[8]).toBe(true);
});

it("still asks the inviter for both names on a server that can't let the joiner choose", async () => {
  await addSomeoneNew({ member_lifecycle_enabled: true });
  fireEvent.change(screen.getByTestId("new-person-name"), { target: { value: "Ayşe" } });
  expect(screen.getByText(t("devices.add.new.nameHintFixed"))).toBeTruthy();
  fireEvent.click(screen.getByTestId("wizard-next"));
  fireEvent.change(screen.getByTestId("device-name"), { target: { value: "Pixel 9" } });
  expect(screen.getByText(t("devices.add.deviceNameFixed"))).toBeTruthy();
  fireEvent.click(screen.getByTestId("wizard-create"));
  await waitFor(() => expect(api.createInvitation).toHaveBeenCalled());
  const call = vi.mocked(api.createInvitation).mock.calls[0];
  expect([call[1], call[2], call[8]]).toEqual(["Ayşe", "Pixel 9", false]);
});

it("titles a waiting code for a new person without a name", () => {
  const code = { id: "c", member_name: "Invited member", device_name: "", recipient_names: true, expires_at_unix: 2_000_000_000 };
  expect(codeTitle(code, [])).toBe(t("devices.codes.newPerson"));
  expect(codeTitle({ ...code, recipient_names: false, member_name: "Ayşe" }, [])).toBe(t("devices.codes.newNamed", { name: "Ayşe" }));
});
