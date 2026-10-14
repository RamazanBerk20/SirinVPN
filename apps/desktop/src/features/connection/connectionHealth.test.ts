import { expect, it } from "vitest";
import { connectionHealth } from "./connectionHealth";

it.each([
  ["idle tunnel", { handshakeRecent: false }, "connected", "notChecked"],
  ["unanswered probe", { probe: { probes_sent: 3, probes_received: 0 } }, "connected", "noReply"],
  ["management outage", { managementAvailable: false }, "connected", "notChecked"],
  ["active transport retry", { reconnecting: true }, "reconnecting", "notChecked"],
  ["recovered traffic", { probe: { probes_sent: 3, probes_received: 3 }, handshakeRecent: true }, "connected", "replied"],
] as const)("uses the same evidence contract on desktop and Android: %s", (_, observation, state, reachability) => {
  const result = connectionHealth({ known: true, established: true, reconnecting: false, ...observation });
  expect(result.state).toBe(state);
  expect(result.reachabilityState).toBe(reachability);
});
