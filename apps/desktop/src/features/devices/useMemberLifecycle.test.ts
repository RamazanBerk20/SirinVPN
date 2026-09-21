import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import type { MemberSummary, MembershipSnapshot } from "../../types";
import { useMemberLifecycle } from "./useMemberLifecycle";

vi.mock("../../api", () => ({
  api: { updateMemberSuspension: vi.fn(), revokeMemberDevices: vi.fn() },
}));
const member: MemberSummary = {
  id: "member",
  name: "Family",
  role: "member",
  devices: [
    {
      id: "phone",
      member_id: "member",
      name: "Phone",
      client_tunnel_address: "10.77.0.3",
    },
    {
      id: "tablet",
      member_id: "member",
      name: "Tablet",
      client_tunnel_address: "10.77.0.4",
    },
  ],
};
const snapshot: MembershipSnapshot = {
  members: [member],
  active_invitations: [],
};
function options() {
  return {
    serverId: "server",
    connected: true,
    available: true,
    accessLevel: "owner" as "owner" | "admin",
    snapshot,
    onSnapshot: vi.fn(),
    onError: vi.fn(),
  };
}
beforeEach(() => {
  vi.resetAllMocks();
  vi.spyOn(window, "confirm").mockReturnValue(true);
  vi.mocked(api.updateMemberSuspension).mockResolvedValue(snapshot);
  vi.mocked(api.revokeMemberDevices).mockResolvedValue(snapshot);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

it("uses the latest member state and confirms the scope of all devices", async () => {
  const initial = options();
  const { result, rerender } = renderHook(useMemberLifecycle, {
    initialProps: initial,
  });
  rerender({
    ...initial,
    snapshot: { ...snapshot, members: [{ ...member, suspended: true }] },
  });
  await act(async () => {
    await result.current.changeMemberSuspension(member);
  });
  expect(api.updateMemberSuspension).toHaveBeenCalledWith(
    "server",
    "member",
    false,
  );
  expect(window.confirm).toHaveBeenCalledWith(
    expect.stringContaining("Reactivate Family"),
  );
  await act(async () => {
    await result.current.revokeMemberDevices(member);
  });
  expect(window.confirm).toHaveBeenCalledWith(
    expect.stringContaining("Revoke all 2 devices"),
  );
  expect(api.revokeMemberDevices).toHaveBeenCalledWith(
    "server",
    "member",
    true,
  );
});

it("blocks unsupported servers, disconnected sessions, removed targets and protected roles", async () => {
  const initial = options();
  const { result, rerender } = renderHook(useMemberLifecycle, {
    initialProps: initial,
  });
  for (const props of [
    { ...initial, available: false },
    { ...initial, connected: false },
    { ...initial, snapshot: { ...snapshot, members: [] } },
    {
      ...initial,
      snapshot: {
        ...snapshot,
        members: [{ ...member, role: "owner" as const }],
      },
    },
    {
      ...initial,
      accessLevel: "admin" as const,
      snapshot: { ...snapshot, members: [{ ...member, administrator: true }] },
    },
  ]) {
    rerender(props);
    await act(async () => {
      await result.current.changeMemberSuspension(member);
      await result.current.revokeMemberDevices(member);
    });
  }
  expect(window.confirm).not.toHaveBeenCalled();
  expect(api.updateMemberSuspension).not.toHaveBeenCalled();
  expect(api.revokeMemberDevices).not.toHaveBeenCalled();
});

it("honors cancellation and serializes duplicate member actions", async () => {
  const initial = options();
  const { result } = renderHook(useMemberLifecycle, { initialProps: initial });
  vi.mocked(window.confirm).mockReturnValueOnce(false);
  await act(async () => {
    await result.current.revokeMemberDevices(member);
  });
  expect(api.revokeMemberDevices).not.toHaveBeenCalled();
  let resolve!: (value: MembershipSnapshot) => void;
  vi.mocked(api.updateMemberSuspension).mockImplementationOnce(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  let pending!: Promise<void>;
  act(() => {
    pending = result.current.changeMemberSuspension(member);
  });
  expect(result.current.memberBusy).toBe("member");
  await act(async () => {
    await result.current.revokeMemberDevices(member);
  });
  expect(api.revokeMemberDevices).not.toHaveBeenCalled();
  await act(async () => {
    resolve(snapshot);
    await pending;
  });
  expect(result.current.memberBusy).toBeNull();
  expect(initial.onSnapshot).toHaveBeenCalledTimes(1);
});

it("does not apply a late response after a server change or disconnect", async () => {
  const initial = options();
  const { result, rerender } = renderHook(useMemberLifecycle, {
    initialProps: initial,
  });
  let resolve!: (value: MembershipSnapshot) => void;
  vi.mocked(api.revokeMemberDevices).mockImplementationOnce(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  let pending!: Promise<void>;
  act(() => {
    pending = result.current.revokeMemberDevices(member);
  });
  await waitFor(() => expect(api.revokeMemberDevices).toHaveBeenCalled());
  rerender({ ...initial, serverId: "other", connected: false });
  await act(async () => {
    resolve(snapshot);
    await pending;
  });
  expect(initial.onSnapshot).not.toHaveBeenCalled();
  expect(result.current.memberBusy).toBeNull();
});

it("keeps the last confirmed snapshot on an uncertain failure and permits a retry", async () => {
  const initial = options();
  const { result } = renderHook(useMemberLifecycle, { initialProps: initial });
  vi.mocked(api.updateMemberSuspension).mockRejectedValueOnce(
    new Error("Connection lost"),
  );
  await act(async () => {
    await result.current.changeMemberSuspension(member);
  });
  expect(initial.onSnapshot).not.toHaveBeenCalled();
  expect(initial.onError).toHaveBeenLastCalledWith("Connection lost");
  expect(result.current.memberBusy).toBeNull();
  await act(async () => {
    await result.current.changeMemberSuspension(member);
  });
  expect(initial.onSnapshot).toHaveBeenCalledWith(snapshot);
});
