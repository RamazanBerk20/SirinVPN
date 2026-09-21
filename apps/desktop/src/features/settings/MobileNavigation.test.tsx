import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { usePageNavigation } from "../../hooks/usePageNavigation";
import { registerNavigationGuard } from "../../lib/navigationGuard";
import { SettingsLayout, type SettingsCategory } from "./SettingsLayout";
import { ActionMenu } from "../../components/ActionMenu";

vi.mock("../../platform", () => ({ isAndroid: true }));
vi.mock("./PreferencesProvider", () => ({ usePreferences: () => ({ snapshot: { preferences: { animations: false } } }) }));
afterEach(cleanup);

it("drills into one mobile settings page, honours navigation guards, and returns with Back", async () => {
  window.history.replaceState({ sirinDepth: 0 }, "", "#settings");
  vi.spyOn(window, "scrollTo").mockImplementation(() => {});
  function Screen() {
    const [page, navigate, detail, back] = usePageNavigation();
    return <SettingsLayout mobile category={(detail || "general") as SettingsCategory} detail={Boolean(detail)} onBack={back} onChange={category => navigate(page, category)}>
      <p>Editing {detail}</p>
    </SettingsLayout>;
  }
  render(<Screen />);
  expect(screen.queryByRole("tablist")).toBeNull();
  expect(screen.queryByText(/^Editing/)).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Connection" }));
  expect(screen.getByText("Editing connection")).toBeTruthy();
  expect(window.location.hash).toBe("#settings/connection");
  const removeGuard = registerNavigationGuard(() => false);
  fireEvent.click(screen.getByRole("button", { name: "Back" }));
  expect(screen.getByText("Editing connection")).toBeTruthy();
  removeGuard();
  fireEvent.click(screen.getByRole("button", { name: "Back" }));
  await waitFor(() => expect(screen.queryByText("Editing connection")).toBeNull());
  expect(screen.getByRole("button", { name: /^VPS maintenance/ })).toBeTruthy();
});

it("opens Android actions in a dismissible sheet and keeps disabled operations disabled", async () => {
  const run = vi.fn();
  render(<ActionMenu label="Server actions" actions={[{ label: "Rename", run }, { label: "Unavailable", disabled: true, run }]} />);
  fireEvent.click(screen.getByRole("button", { name: "Server actions" }));
  expect(await screen.findByRole("dialog", { name: "Server actions" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Unavailable" }));
  expect(run).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Rename" }));
  expect(run).toHaveBeenCalledOnce();
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
});
