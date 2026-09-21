import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../api";
import { useSshLogin } from "./useSshLogin";
import type { SavedSshLogin } from "../types";

vi.mock("../api", () => ({
  api: { getSshLogin: vi.fn(), saveSshLogin: vi.fn(), forgetSshLogin: vi.fn() },
}));
const fingerprint = `SHA256:${"A".repeat(43)}`;
const saved: SavedSshLogin = {
  username: "admin",
  ssh_port: 2222,
  authentication: "password",
  private_key_path: null,
};
beforeEach(() => {
  vi.useFakeTimers();
  vi.resetAllMocks();
  vi.mocked(api.getSshLogin).mockResolvedValue(null);
  vi.mocked(api.saveSshLogin).mockResolvedValue(saved);
  vi.mocked(api.forgetSshLogin).mockResolvedValue(undefined);
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});
const load = () =>
  act(async () => {
    await vi.advanceTimersByTimeAsync(250);
  });

it("defaults new logins to Password and keeps fast lookups quiet while typing", async () => {
  const { result, rerender } = renderHook(({ host }) => useSshLogin(host), { initialProps: { host: "" } });
  expect(result.current.auth).toBe("password");
  for (const host of ["v", "vp", "vps", "vps.example"]) {
    rerender({ host });
    expect(result.current.valid).toBe(false);
    expect(result.current.checkingSavedLogin).toBe(false);
    await act(async () => { await vi.advanceTimersByTimeAsync(100); });
  }
  expect(api.getSshLogin).not.toHaveBeenCalled();
  await load();
  expect(api.getSshLogin).toHaveBeenCalledExactlyOnceWith("vps.example");
  expect(result.current.loading).toBe(false);
  expect(result.current.checkingSavedLogin).toBe(false);
  act(() => { result.current.setPassword("test-password"); result.current.setRemember(false); });
  await expect(result.current.prepare(fingerprint)).resolves.toMatchObject({ authentication: "password", password: "test-password" });
});

it("shows only slow saved-login checks and discards their progress when the destination changes", async () => {
  let finish!: (login: SavedSshLogin) => void;
  vi.mocked(api.getSshLogin).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const { result, rerender } = renderHook(({ host }) => useSshLogin(host), { initialProps: { host: "old.example" } });
  await load();
  expect(result.current.loading).toBe(true);
  expect(result.current.checkingSavedLogin).toBe(false);
  await act(async () => { await vi.advanceTimersByTimeAsync(500); });
  expect(result.current.checkingSavedLogin).toBe(true);
  rerender({ host: "new.example" });
  expect(result.current.checkingSavedLogin).toBe(false);
  await act(async () => finish(saved));
  await load();
  expect(result.current.checkingSavedLogin).toBe(false);
  expect(result.current.saved).toBeNull();
  expect(result.current.auth).toBe("password");
});

it("preserves a saved private-key method instead of replacing it with the new default", async () => {
  vi.mocked(api.getSshLogin).mockResolvedValue({ ...saved, authentication: "private_key", private_key_path: "/home/example/.ssh/vps" });
  const { result } = renderHook(() => useSshLogin("vps.example"));
  await load();
  expect(result.current.auth).toBe("private_key");
  expect(result.current.keyPath).toBe("/home/example/.ssh/vps");
  expect(result.current.usingSaved).toBe(true);
});

it("uses a saved login and its SSH port without exposing or asking for a password", async () => {
  vi.mocked(api.getSshLogin).mockResolvedValue(saved);
  const { result } = renderHook(() => useSshLogin("vps.example"));
  await load();
  expect(result.current.valid).toBe(true);
  expect(result.current.port).toBe("2222");
  expect(result.current.password).toBe("");
  await expect(result.current.prepare(fingerprint)).resolves.toMatchObject({
    authentication: "saved",
    password: null,
    sudo_password: null,
    host_key_sha256: fingerprint,
  });
  expect(api.saveSshLogin).not.toHaveBeenCalled();
});

it("remembers a newly entered login once and keeps it available after operation cleanup", async () => {
  const { result } = renderHook(() => useSshLogin("vps.example"));
  await load();
  act(() => {
    result.current.setAuth("password");
    result.current.setUsername("admin");
    result.current.setPort("2222");
    result.current.setPassword("test-password");
    result.current.setSudoPassword("test-sudo");
  });
  await act(async () => {
    const input = await result.current.prepare(fingerprint);
    expect(input.authentication).toBe("saved");
    expect(input.password).toBeNull();
  });
  expect(api.saveSshLogin).toHaveBeenCalledWith(
    expect.objectContaining({
      host: "vps.example",
      password: "test-password",
      sudo_password: "test-sudo",
      host_key_sha256: fingerprint,
    }),
  );
  act(() => result.current.clearSecrets());
  expect(result.current.usingSaved).toBe(true);
  await expect(result.current.prepare(fingerprint)).resolves.toMatchObject({
    authentication: "saved",
  });
  expect(api.saveSshLogin).toHaveBeenCalledTimes(1);
});

it("permits a one-time login when remembering is disabled", async () => {
  const { result } = renderHook(() => useSshLogin("vps.example"));
  await load();
  act(() => {
    result.current.setAuth("password");
    result.current.setPassword("test-password");
    result.current.setRemember(false);
  });
  await expect(result.current.prepare(fingerprint)).resolves.toMatchObject({
    authentication: "password",
    password: "test-password",
  });
  expect(api.saveSshLogin).not.toHaveBeenCalled();
});

it("stops before maintenance when authentication or wallet storage fails", async () => {
  vi.mocked(api.saveSshLogin).mockRejectedValue(
    new Error("Unlock your desktop wallet."),
  );
  const { result } = renderHook(() => useSshLogin("vps.example"));
  await load();
  act(() => result.current.setAuth("agent"));
  await expect(result.current.prepare(fingerprint)).rejects.toThrow(
    "Unlock your desktop wallet.",
  );
  expect(result.current.usingSaved).toBe(false);
});

it("restores saved metadata after editing and removes the saved login when forgotten", async () => {
  vi.mocked(api.getSshLogin).mockResolvedValue(saved);
  const { result } = renderHook(() => useSshLogin("vps.example"));
  await load();
  act(() => result.current.edit());
  act(() => {
    result.current.setPort("22");
    result.current.setUsername("root");
  });
  act(() => result.current.reuse());
  expect(result.current.port).toBe("2222");
  expect(result.current.username).toBe("admin");
  await act(async () => result.current.forget());
  expect(api.forgetSshLogin).toHaveBeenCalledWith("vps.example");
  expect(result.current.usingSaved).toBe(false);
  expect(result.current.valid).toBe(false);
});

it("does not use a lookup result for a previous destination", async () => {
  let resolve!: (value: SavedSshLogin) => void;
  vi.mocked(api.getSshLogin).mockImplementationOnce(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  const { result, rerender } = renderHook(({ host }) => useSshLogin(host), {
    initialProps: { host: "old.example" },
  });
  await load();
  rerender({ host: "new.example" });
  await act(async () => resolve(saved));
  await load();
  expect(result.current.usingSaved).toBe(false);
  expect(result.current.username).toBe("root");
});

it("cancels preparation when the dialog closes while a login is being saved", async () => {
  let resolve!: (value: SavedSshLogin) => void;
  vi.mocked(api.saveSshLogin).mockImplementation(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  const { result, rerender } = renderHook(
    ({ active }) => useSshLogin("vps.example", active),
    { initialProps: { active: true } },
  );
  await load();
  act(() => result.current.setAuth("agent"));
  const pending = result.current.prepare(fingerprint);
  const rejected = expect(pending).rejects.toThrow("cancelled");
  rerender({ active: false });
  await act(async () => resolve(saved));
  await rejected;
});
