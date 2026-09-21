import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import { useSshLogin } from "../../hooks/useSshLogin";
import { SshLoginFields } from "./SshLoginFields";

vi.mock("../../api", () => ({ api: { getSshLogin: vi.fn() } }));
afterEach(() => { cleanup(); vi.useRealTimers(); vi.resetAllMocks(); });
function Form() { return <SshLoginFields login={useSshLogin("vps.example")} />; }

it("keeps credential fields in place and disables them while a saved-login lookup is pending", async () => {
  vi.useFakeTimers();
  let finish!: (value: null) => void;
  vi.mocked(api.getSshLogin).mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
  render(<Form />);
  const username = screen.getByLabelText("SSH username");
  const password = screen.getByLabelText("SSH password");
  expect(username.matches(":disabled")).toBe(true);
  expect(screen.queryByText("Checking for a saved SSH login…")).toBeNull();
  expect(screen.getAllByRole("button").map(button => button.textContent)).toEqual(["Password", "SSH agent", "Private key"]);
  expect(screen.getByRole("button", { name: "Password" }).getAttribute("aria-pressed")).toBe("true");
  await act(async () => { await vi.advanceTimersByTimeAsync(250); });
  expect(screen.getByLabelText("SSH username")).toBe(username);
  expect(screen.getByLabelText("SSH password")).toBe(password);
  expect(screen.queryByText("Checking for a saved SSH login…")).toBeNull();
  await act(async () => { await vi.advanceTimersByTimeAsync(500); });
  expect(screen.getByRole("status").textContent).toBe("Checking for a saved SSH login…");
  await act(async () => { finish(null); });
  expect(screen.getByLabelText("SSH username")).toBe(username);
  expect(screen.getByLabelText("SSH password")).toBe(password);
  expect(screen.queryByText("Checking for a saved SSH login…")).toBeNull();
  expect(username.matches(":disabled")).toBe(false);
});
