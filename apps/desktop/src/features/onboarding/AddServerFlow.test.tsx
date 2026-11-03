import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { AddServerFlow } from "./AddServerFlow";
import { t } from "../../i18n";

vi.mock("../../api", () => ({ api: { getSshLogin: vi.fn().mockResolvedValue(null) } }));
afterEach(cleanup);

it("starts on the described options and returns to them from a flow", () => {
  render(<AddServerFlow onAdded={vi.fn()} />);
  const options = screen.getByRole("group", { name: t("onboarding.choice.listLabel") });
  for (const choice of ["join", "provision", "backup", "recovery"] as const)
    expect(options.textContent).toContain(t(`onboarding.choice.${choice}.title`));
  // Creating a Hetzner server needs a paid account, so it waits under Advanced.
  expect(options.textContent).not.toContain(t("onboarding.choice.hetzner.title"));
  const advanced = screen.getByText(t("onboarding.choice.advanced")).closest("details")!;
  expect(advanced.open).toBe(false);
  expect(advanced.textContent).toContain(t("onboarding.choice.hetzner.title"));

  fireEvent.click(screen.getByRole("button", { name: new RegExp(t("onboarding.choice.provision.title")) }));
  expect(screen.queryByRole("group", { name: t("onboarding.choice.listLabel") })).toBeNull();
  expect(screen.getByLabelText(t("onboarding.setup.host"))).toBeTruthy();

  fireEvent.click(screen.getByRole("button", { name: t("onboarding.choice.back") }));
  expect(screen.getByRole("group", { name: t("onboarding.choice.listLabel") })).toBeTruthy();
});

it("opens the requested flow directly", () => {
  render(<AddServerFlow onAdded={vi.fn()} initialMode="backup" />);
  expect(screen.queryByRole("group", { name: t("onboarding.choice.listLabel") })).toBeNull();
  expect(screen.getByRole("button", { name: t("onboarding.choice.back") })).toBeTruthy();
});
