import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { emptyLocalStatus } from "../../hooks/useDesktopStatus";
import { t } from "../../i18n";
import type { LocalTunnelStatus } from "../../types";
import { pendingCommand } from "./connectionCommands";
import { connectionView } from "./connectionView";
import { MaintenanceReview } from "./MaintenanceReview";
import type { ServerWorkspaceModel } from "./useServerWorkspace";

const disconnect = vi.hoisted(() => vi.fn());
vi.mock("../../api", () => ({ api: { disconnect } }));
afterEach(cleanup);

it("disconnects through the shared command, so Home and the sidebar show Disconnecting", async () => {
  let finish!: (status: LocalTunnelStatus) => void;
  disconnect.mockReturnValue(new Promise((resolve) => { finish = resolve; }));
  const local = { ...emptyLocalStatus, state: "connected" as const, server_id: "a" };
  const model = { maintenanceReview: "update", localStatus: local, localKnown: true, rotationPending: false,
    profile: { id: "a", name: "VPS" }, onRefresh: vi.fn().mockResolvedValue(undefined), setMaintenanceReview: vi.fn() } as unknown as ServerWorkspaceModel;
  render(<MaintenanceReview model={model} />);
  fireEvent.click(screen.getByRole("button", { name: t("maintenance.review.disconnect") }));
  expect(connectionView(local, "a", pendingCommand())).toEqual({ phase: "stopping" });
  finish(emptyLocalStatus);
  await vi.waitFor(() => expect(pendingCommand()).toBeNull());
});
