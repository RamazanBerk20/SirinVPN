import { expect, it } from "vitest";
import { connectionHealth } from "./connectionHealth";

it.each([
  ["idle tunnel", { handshakeRecent: false }, "Connected", "Reachability not verified"],
  ["unanswered probe", { probe: { probes_sent: 3, probes_received: 0 } }, "Connected", "Last path probe unanswered"],
  ["management outage", { managementAvailable: false }, "Connected", "Reachability not verified"],
  ["active transport retry", { reconnecting: true }, "Reconnecting", "Reachability not verified"],
  ["recovered traffic", { probe: { probes_sent: 3, probes_received: 3 }, handshakeRecent: true }, "Connected", "Last path probe replied"],
] as const)("uses the same evidence contract on desktop and Android: %s", (_, observation, status, reachability) => {
  const result = connectionHealth({ known: true, established: true, reconnecting: false, ...observation });
  expect(result.status).toBe(status);
  expect(result.reachability).toBe(reachability);
});
