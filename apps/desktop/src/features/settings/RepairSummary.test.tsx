import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import type { RepairResult, ServerProfile } from "../../types";
import { RepairSummary } from "./RepairSummary";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
it("distinguishes the preserved server identity from the installed software hash", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  vi.stubGlobal("navigator", { clipboard: { writeText } });
  const result = { server_identity_fingerprint: "a".repeat(64), artifact_sha256: "b".repeat(64), dns_upstream: { mode: "recursive" }, private_dns_records: [], events: [] } as RepairResult;
  render(<RepairSummary profile={{ name: "My VPS" } as ServerProfile} result={result} dnsPreserved={false} recordsPreserved={false} />);
  const preserved = screen.getByRole("region", { name: "Preserved" });
  expect(within(preserved).queryByText("Private DNS policy")).toBeNull();
  expect(within(preserved).queryByText("Private DNS records")).toBeNull();
  expect(screen.getByText("None configured")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Copy server identity fingerprint" }));
  await waitFor(() => expect(writeText).toHaveBeenCalledWith("a".repeat(64)));
  fireEvent.click(within(preserved).getByRole("button", { name: "Show full" }));
  expect(within(preserved).getByText("a".repeat(64))).toBeTruthy();
  expect(within(preserved).queryByText("b".repeat(64))).toBeNull();
});
