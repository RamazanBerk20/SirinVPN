import { expect, it, vi } from "vitest";
import { diagnosticFixes } from "./WorkspaceDialogs";
import { t } from "../../i18n";

it("offers to turn on VPS security updates only where a repair can do it", () => {
  const turnOn = vi.fn();
  const owner = diagnosticFixes(vi.fn(), turnOn);
  expect(owner.os_security_updates?.label).toBe(t("maintenance.diagnostics.turnOnUpdates"));
  owner.os_security_updates?.run();
  expect(turnOn).toHaveBeenCalledOnce();
  // Members and admins can't repair the VPS, so their warning has no button.
  expect(diagnosticFixes(vi.fn())).not.toHaveProperty("os_security_updates");
});
