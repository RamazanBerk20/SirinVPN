import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../api";
import { useSshOperation } from "./useSshOperation";

vi.mock("../api", () => ({
  api: { getSshLogin: vi.fn(), saveSshLogin: vi.fn(), forgetSshLogin: vi.fn(), inspectSshHost: vi.fn(), trustSshHost: vi.fn() },
}));
const fingerprint = `SHA256:${"A".repeat(43)}`;

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.getSshLogin).mockResolvedValue(null);
  vi.mocked(api.saveSshLogin).mockResolvedValue({ username: "root", ssh_port: 22, authentication: "password", private_key_path: null });
  vi.mocked(api.inspectSshHost).mockResolvedValue({ fingerprint, status: "trusted" });
});
afterEach(cleanup);

async function signedIn() {
  const hook = renderHook(() => useSshOperation<string>("vps.example", true));
  await waitFor(() => expect(hook.result.current.login.state).toBe("editing"));
  act(() => hook.result.current.login.setPassword("typed-password"));
  await act(() => hook.result.current.verify("unreachable", () => {}));
  return hook;
}

it("saves a remembered login only after the operation succeeded, once", async () => {
  const { result } = await signedIn();
  const task = vi.fn().mockRejectedValueOnce(new Error("SSH authentication failed.")).mockResolvedValue("done");
  await act(() => result.current.run(task, "failed"));
  // The caller's summary first; the backend's text is detail on its own line.
  expect(result.current.state).toMatchObject({ kind: "failed", error: "failed\nSSH authentication failed.", returnTo: "form" });
  expect(api.saveSshLogin).not.toHaveBeenCalled();

  act(() => result.current.login.setPassword("typed-password"));
  await act(() => result.current.verify("unreachable", () => {}));
  await act(() => result.current.run(task, "failed"));
  expect(result.current.state).toEqual({ kind: "succeeded", result: "done" });
  expect(api.saveSshLogin).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ host: "vps.example", password: "typed-password" }));
  expect(task.mock.invocationCallOrder[1]).toBeLessThan(vi.mocked(api.saveSshLogin).mock.invocationCallOrder[0]);
});

it("doesn't save when the result says the login wasn't proven", async () => {
  const { result } = await signedIn();
  await act(() => result.current.run(async () => "legacy", "failed", { loginWorked: () => false, keepSecrets: true }));
  expect(result.current.state.kind).toBe("succeeded");
  expect(api.saveSshLogin).not.toHaveBeenCalled();
  expect(result.current.login.password).toBe("typed-password");
});
