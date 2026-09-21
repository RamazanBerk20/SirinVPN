import { afterEach, expect, it, vi } from "vitest";
import { api } from "./api";
const native = vi.hoisted(() => ({
  invoke: vi.fn(),
  channels: [] as { onmessage: (event: unknown) => void }[],
}));
vi.mock("@tauri-apps/api/core", () => ({
  invoke: native.invoke,
  Channel: class {
    onmessage = (_event: unknown) => {};
    constructor() {
      native.channels.push(this);
    }
  },
}));
afterEach(() => {
  vi.resetAllMocks();
  native.channels.length = 0;
});

it("cancels a subscription even when its start acknowledgement arrives after cleanup", async () => {
  let acknowledge!: () => void;
  native.invoke.mockImplementation((command) =>
    command === "subscribe_server_status"
      ? new Promise<void>((resolve) => {
          acknowledge = resolve;
        })
      : Promise.resolve(),
  );
  const receive = vi.fn();
  const stop = api.watchServerStatus("first", receive);
  const id = native.invoke.mock.calls[0][1].subscriptionId;
  stop();
  native.channels[0].onmessage({ kind: "state", state: "connecting" });
  expect(receive).not.toHaveBeenCalled();
  expect(native.invoke).toHaveBeenCalledTimes(1);
  acknowledge();
  await vi.waitFor(() =>
    expect(native.invoke).toHaveBeenCalledWith("unsubscribe_server_status", {
      subscriptionId: id,
    }),
  );
});

it("cleans up a local channel when the window hides before subscription completes", async () => {
  let acknowledge!: () => void;
  native.invoke.mockImplementation(command => command === "subscribe_local_status"
    ? new Promise<void>(resolve => { acknowledge = resolve; }) : Promise.resolve());
  const receive = vi.fn();
  const stop = api.watchLocalStatus(receive);
  const id = native.invoke.mock.calls[0][1].subscriptionId;
  stop();
  native.channels[0].onmessage({ status: null, stale: true });
  expect(receive).not.toHaveBeenCalled();
  acknowledge();
  await vi.waitFor(() => expect(native.invoke).toHaveBeenCalledWith("unsubscribe_local_status", { subscriptionId: id }));
});
