import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import type { RepairResult, ServerProfile } from "../../types";
import { RepairSummary } from "./RepairSummary";
import { t } from "../../i18n";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
it("distinguishes the preserved server identity from the installed software hash", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  vi.stubGlobal("navigator", { clipboard: { writeText } });
  const result = { server_identity_fingerprint: "a".repeat(64), artifact_sha256: "b".repeat(64), dns_upstream: { mode: "recursive" }, private_dns_records: [], events: [] } as RepairResult;
  render(<RepairSummary profile={{ name: "My VPS" } as ServerProfile} result={result} dnsPreserved={false} recordsPreserved={false} />);
  const preserved = screen.getByRole("region", { name: t("vps.summary.preserved") });
  expect(within(preserved).queryByText(t("vps.summary.dnsPolicy"))).toBeNull();
  expect(within(preserved).queryByText(t("vps.summary.dnsRecords"))).toBeNull();
  expect(screen.getByText(t("vps.summary.recordsNone"))).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: new RegExp(t("vps.summary.fingerprint"), "i") }));
  await waitFor(() => expect(writeText).toHaveBeenCalledWith("a".repeat(64)));
  fireEvent.click(within(preserved).getByRole("button", { name: t("app.copy.showAll") }));
  expect(within(preserved).getByText("a".repeat(64))).toBeTruthy();
  expect(within(preserved).queryByText("b".repeat(64))).toBeNull();
});
