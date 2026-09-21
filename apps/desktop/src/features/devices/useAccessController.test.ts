import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import type {
  CurrentConfiguration,
  MembershipSnapshot,
  ServerProfile,
} from "../../types";
import { useAccessController } from "./useAccessController";
import { clearMembershipCache } from "./membershipCache";
import * as dialog from "@tauri-apps/plugin-dialog";

vi.mock("@tauri-apps/plugin-dialog", () => ({ confirm: vi.fn() }));
vi.mock("../../api", () => ({
  api: {
    membership: vi.fn(),
    serverConfiguration: vi.fn(),
    updateMemberSuspension: vi.fn(),
    revokeDevice: vi.fn(),
  },
}));
afterEach(() => {
  clearMembershipCache();
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

function pendingNativeConfirmation() {
  vi.stubGlobal("__TAURI_INTERNALS__", {});
  let answer!: (confirmed: boolean) => void;
  vi.mocked(dialog.confirm).mockImplementationOnce(() => new Promise<boolean>(resolve => { answer = resolve; }));
  return (confirmed: boolean) => answer(confirmed);
}

it("shows membership before a slow configuration request finishes", async () => {
  const snapshot = { members: [], active_invitations: [] };
  vi.mocked(api.membership).mockResolvedValue(snapshot);
  let finish!: (value: CurrentConfiguration) => void;
  vi.mocked(api.serverConfiguration).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const { result } = renderHook(useAccessController, { initialProps: confirmationProps() });
  await waitFor(() => expect(result.current.snapshot).toBe(snapshot));
  expect(result.current.loading).toBe(false);
  expect(result.current.recipientNamesAvailable).toBeNull();
  await act(async () => finish({ recipient_names_enabled: true }));
  expect(result.current.recipientNamesAvailable).toBe(true);
});

it("immediately shows saved membership on return without treating it as current authorization", async () => {
  const snapshot = { members: [], active_invitations: [] };
  vi.mocked(api.membership).mockResolvedValue(snapshot);
  vi.mocked(api.serverConfiguration).mockResolvedValue({});
  const first = renderHook(useAccessController, { initialProps: confirmationProps() });
  await waitFor(() => expect(first.result.current.verified).toBe(true));
  first.unmount();
  let finish!: (value: MembershipSnapshot) => void;
  vi.mocked(api.membership).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const second = renderHook(useAccessController, { initialProps: confirmationProps() });
  expect(second.result.current.snapshot).toEqual(snapshot);
  expect(second.result.current.verified).toBe(false);
  await act(async () => finish(snapshot));
  expect(second.result.current.verified).toBe(true);
});

it("shares an in-flight membership read and does not reuse it for another identity", async () => {
  let finish!: (value: MembershipSnapshot) => void;
  vi.mocked(api.membership).mockReset().mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  vi.mocked(api.serverConfiguration).mockResolvedValue({});
  const first = renderHook(useAccessController, { initialProps: confirmationProps() });
  const second = renderHook(useAccessController, { initialProps: confirmationProps() });
  expect(api.membership).toHaveBeenCalledTimes(1);
  await act(async () => finish({ members: [], active_invitations: [] }));
  first.unmount(); second.unmount();
  const props = confirmationProps();
  const other = renderHook(useAccessController, { initialProps: { ...props, profile: { ...props.profile, device_id: "different" } } });
  expect(other.result.current.snapshot).toBeNull();
  expect(other.result.current.verified).toBe(false);
  await act(async () => finish({ members: [], active_invitations: [] }));
});

const confirmationProps = () => ({
  profile: { id: "server", name: "My VPS", device_id: "self" },
  connected: true,
  accessLevel: "owner" as "owner" | "admin",
  onAccessChanged: vi.fn(async () => {}),
});

it("keeps access failures visible through polling retries until membership is verified again", async () => {
  vi.useFakeTimers();
  const snapshot: MembershipSnapshot = { members: [{
    id: "member", name: "Member", role: "member", devices: [{
      id: "self", member_id: "member", name: "This device", client_tunnel_address: "10.77.0.2", recent_handshake: true,
    }],
  }], active_invitations: [] };
  vi.mocked(api.membership).mockReset().mockResolvedValue(snapshot);
  vi.mocked(api.serverConfiguration).mockResolvedValue({ recipient_names_enabled: true });
  const { result } = renderHook(useAccessController, { initialProps: confirmationProps() });
  await act(async () => {});
  expect(result.current.verified).toBe(true);
  const failure = "the private management connection failed";
  vi.mocked(api.membership).mockRejectedValue(new Error(failure));
  await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
  expect(result.current.loadError).toBe(failure);
  expect(result.current.verified).toBe(false);
  expect(result.current.snapshot?.members[0].devices[0].recent_handshake).toBeUndefined();

  let fail!: (reason: Error) => void;
  vi.mocked(api.membership).mockImplementationOnce(() => new Promise((_, reject) => { fail = reject; }));
  await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
  expect(result.current.loading).toBe(true);
  expect(result.current.loadError).toBe(failure);
  expect(result.current.verified).toBe(false);
  await act(async () => fail(new Error(failure)));
  expect(result.current.loading).toBe(false);
  expect(result.current.loadError).toBe(failure);

  vi.mocked(api.membership).mockResolvedValue(snapshot);
  await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
  expect(result.current.loadError).toBeNull();
  expect(result.current.verified).toBe(true);
  expect(result.current.snapshot).toBe(snapshot);
  expect(api.membership).toHaveBeenCalledTimes(4);
});

it("keeps a configuration failure until configuration succeeds, independently of membership", async () => {
  vi.mocked(api.membership).mockResolvedValue({ members: [], active_invitations: [] });
  vi.mocked(api.serverConfiguration).mockRejectedValue(new Error("Configuration unavailable"));
  const { result } = renderHook(useAccessController, { initialProps: confirmationProps() });
  await waitFor(() => expect(result.current.loadError).toBe("Configuration unavailable"));
  expect(result.current.verified).toBe(true);
  expect(result.current.recipientNamesAvailable).toBeNull();

  let finish!: (configuration: CurrentConfiguration) => void;
  vi.mocked(api.serverConfiguration).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  let pending!: Promise<void>;
  await act(async () => { pending = result.current.refresh(); });
  expect(result.current.loading).toBe(false);
  expect(result.current.loadError).toBe("Configuration unavailable");
  await act(async () => { finish({ recipient_names_enabled: true }); await pending; });
  expect(result.current.loadError).toBeNull();
  expect(result.current.recipientNamesAvailable).toBe(true);
});

it("does not let a late configuration success hide a failed membership read", async () => {
  vi.mocked(api.membership).mockRejectedValue(new Error("Access unavailable"));
  let finish!: (configuration: CurrentConfiguration) => void;
  vi.mocked(api.serverConfiguration).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const { result } = renderHook(useAccessController, { initialProps: confirmationProps() });
  await waitFor(() => expect(result.current.loadError).toBe("Access unavailable"));
  await act(async () => finish({ recipient_names_enabled: true }));
  expect(result.current.loadError).toBe("Access unavailable");
  expect(result.current.verified).toBe(false);
  expect(result.current.loading).toBe(false);
});

it.each(["server", "disconnect"])("discards old read failures after a %s change", async change => {
  let failMembership!: (reason: Error) => void;
  let failConfiguration!: (reason: Error) => void;
  vi.mocked(api.membership).mockResolvedValue({ members: [], active_invitations: [] })
    .mockImplementationOnce(() => new Promise((_, reject) => { failMembership = reject; }));
  vi.mocked(api.serverConfiguration).mockResolvedValue({ recipient_names_enabled: true })
    .mockImplementationOnce(() => new Promise((_, reject) => { failConfiguration = reject; }));
  const props = confirmationProps();
  const { result, rerender } = renderHook(useAccessController, { initialProps: props });
  rerender(change === "server" ? { ...props, profile: { ...props.profile, id: "other" } } : { ...props, connected: false });
  await act(async () => {
    failMembership(new Error("Old access failure"));
    failConfiguration(new Error("Old configuration failure"));
  });
  expect(result.current.loadError).toBeNull();
  expect(result.current.loading).toBe(false);
  expect(result.current.verified).toBe(change === "server");
});

it("keeps an OS confirmation valid across background membership refreshes", async () => {
  const snapshot = { members: [], active_invitations: [] };
  vi.mocked(api.membership).mockResolvedValue(snapshot);
  vi.mocked(api.serverConfiguration).mockResolvedValue({});
  vi.mocked(api.revokeDevice).mockReset().mockResolvedValue(snapshot);
  const { result } = renderHook(useAccessController, { initialProps: confirmationProps() });
  await waitFor(() => expect(result.current.snapshot).toBe(snapshot));
  const answer = pendingNativeConfirmation();
  let pending!: Promise<void>;
  act(() => { pending = result.current.revoke("phone", "Phone"); });
  await act(async () => { await result.current.refresh(); });
  await act(async () => { answer(true); await pending; });
  expect(api.revokeDevice).toHaveBeenCalledExactlyOnceWith("server", "phone");
});

it.each(["server", "disconnect", "access", "unmount"])("ignores an OS confirmation after %s changes its scope", async (change) => {
  const snapshot = { members: [], active_invitations: [] };
  vi.mocked(api.membership).mockResolvedValue(snapshot);
  vi.mocked(api.serverConfiguration).mockResolvedValue({});
  vi.mocked(api.revokeDevice).mockReset().mockResolvedValue(snapshot);
  const props = confirmationProps();
  const { result, rerender, unmount } = renderHook(useAccessController, { initialProps: props });
  await waitFor(() => expect(result.current.snapshot).toBe(snapshot));
  const answer = pendingNativeConfirmation();
  let pending!: Promise<void>;
  act(() => { pending = result.current.revoke("phone", "Phone"); });
  if (change === "server") rerender({ ...props, profile: { ...props.profile, id: "another" } });
  if (change === "disconnect") rerender({ ...props, connected: false });
  if (change === "access") rerender({ ...props, accessLevel: "admin" });
  if (change === "unmount") unmount();
  await act(async () => { answer(true); await pending; });
  expect(api.revokeDevice).not.toHaveBeenCalled();
});

it("treats missing naming support as an older server only after a successful configuration read", async () => {
  vi.mocked(api.membership).mockResolvedValue({ members: [], active_invitations: [] });
  vi.mocked(api.serverConfiguration).mockResolvedValue({});
  const { result } = renderHook(() => useAccessController({
    profile: { id: "server" } as ServerProfile, connected: true, accessLevel: "owner", onAccessChanged: vi.fn(),
  }));
  expect(result.current.recipientNamesAvailable).toBeNull();
  await waitFor(() => expect(result.current.recipientNamesAvailable).toBe(false));
  vi.mocked(api.serverConfiguration).mockRejectedValueOnce(new Error("Unavailable"));
  await act(async () => { await result.current.refresh(); });
  expect(result.current.recipientNamesAvailable).toBeNull();
  expect(result.current.loadError).toBe("Unavailable");
  vi.mocked(api.serverConfiguration).mockResolvedValue({ recipient_names_enabled: true });
  await act(async () => { await result.current.refresh(); });
  expect(result.current.recipientNamesAvailable).toBe(true);
});

it("does not reuse another server's invitation capability while its configuration loads", async () => {
  vi.mocked(api.membership).mockResolvedValue({ members: [], active_invitations: [] });
  vi.mocked(api.serverConfiguration).mockResolvedValue({ recipient_names_enabled: true });
  const { result, rerender } = renderHook(({ serverId }) => useAccessController({
    profile: { id: serverId } as ServerProfile, connected: true, accessLevel: "owner", onAccessChanged: vi.fn(),
  }), { initialProps: { serverId: "first" } });
  await waitFor(() => expect(result.current.recipientNamesAvailable).toBe(true));
  let complete!: (value: CurrentConfiguration) => void;
  vi.mocked(api.serverConfiguration).mockImplementationOnce(() => new Promise((resolve) => { complete = resolve; }));
  rerender({ serverId: "second" });
  expect(result.current.recipientNamesAvailable).toBeNull();
  await act(async () => { complete({}); });
  expect(result.current.recipientNamesAvailable).toBe(false);
});

it("keeps a successful suspension when an older access refresh finishes afterwards", async () => {
  const member = {
    id: "family",
    name: "Family",
    role: "member" as const,
    devices: [],
  };
  const active: MembershipSnapshot = {
    members: [member],
    active_invitations: [],
  };
  const suspended: MembershipSnapshot = {
    ...active,
    members: [{ ...member, suspended: true }],
  };
  vi.spyOn(window, "confirm").mockReturnValue(true);
  vi.mocked(api.membership).mockResolvedValue(active);
  vi.mocked(api.serverConfiguration).mockResolvedValue({
    member_lifecycle_enabled: true,
  } as CurrentConfiguration);
  vi.mocked(api.updateMemberSuspension).mockResolvedValue(suspended);
  const { result } = renderHook(() =>
    useAccessController({
      profile: { id: "server" } as ServerProfile,
      connected: true,
      accessLevel: "owner",
      onAccessChanged: vi.fn(),
    }),
  );
  await waitFor(() => expect(result.current.snapshot).toBe(active));
  let resolve!: (value: MembershipSnapshot) => void;
  vi.mocked(api.membership).mockImplementationOnce(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  let refresh!: Promise<void>;
  act(() => {
    refresh = result.current.refresh();
  });
  await act(async () => {
    await result.current.changeMemberSuspension(member);
  });
  expect(result.current.snapshot).toBe(suspended);
  await act(async () => {
    resolve(active);
    await refresh;
  });
  expect(result.current.snapshot).toBe(suspended);
  expect(result.current.loading).toBe(false);
});
