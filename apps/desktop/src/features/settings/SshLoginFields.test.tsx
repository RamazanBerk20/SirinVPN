import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../../api";
import { useSshLogin } from "../../hooks/useSshLogin";
import { SshLoginFields } from "./SshLoginFields";
import { t } from "../../i18n";

vi.mock("../../api", () => ({ api: { getSshLogin: vi.fn() } }));
afterEach(() => { cleanup(); vi.useRealTimers(); vi.resetAllMocks(); });
function Form() { return <SshLoginFields login={useSshLogin("vps.example")} />; }

it("keeps credential fields in place and disables them while a saved-login lookup is pending", async () => {
  vi.useFakeTimers();
  let finish!: (value: null) => void;
  vi.mocked(api.getSshLogin).mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
  render(<Form />);
  const username = screen.getByLabelText(t("ssh.login.username"));
  const password = screen.getByLabelText(t("ssh.login.password"));
  expect(username.matches(":disabled")).toBe(true);
  expect(screen.queryByText(t("ssh.login.checking"))).toBeNull();
  expect(screen.getAllByRole("button").map(button => button.textContent)).toEqual([t("ssh.auth.password"), t("ssh.auth.agent"), t("ssh.auth.privateKey")]);
  expect(screen.getByRole("button", { name: t("ssh.auth.password") }).getAttribute("aria-pressed")).toBe("true");
  await act(async () => { await vi.advanceTimersByTimeAsync(250); });
  expect(screen.getByLabelText(t("ssh.login.username"))).toBe(username);
  expect(screen.getByLabelText(t("ssh.login.password"))).toBe(password);
  expect(screen.queryByText(t("ssh.login.checking"))).toBeNull();
  await act(async () => { await vi.advanceTimersByTimeAsync(500); });
  expect(screen.getByRole("status").textContent).toBe(t("ssh.login.checking"));
  await act(async () => { finish(null); });
  expect(screen.getByLabelText(t("ssh.login.username"))).toBe(username);
  expect(screen.getByLabelText(t("ssh.login.password"))).toBe(password);
  expect(screen.queryByText(t("ssh.login.checking"))).toBeNull();
  expect(username.matches(":disabled")).toBe(false);
});
