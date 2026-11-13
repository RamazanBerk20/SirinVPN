import { describe, expect, it } from "vitest";
import type { CreatedHetznerServer, HetznerReady } from "../../types";
import { hetznerReducer, hetznerUnresolved, type HetznerEvent, type HetznerState } from "./hetznerMachine";

const created: CreatedHetznerServer = { server: { id: 1, name: "sirinvpn-01", host_key_sha256: "SHA256:a" }, private_key_path: null };
const ready: HetznerReady = { ipv4: "203.0.113.7", ipv6: null, host_key_sha256: "SHA256:b" };

const states: Record<string, HetznerState> = {
  plan: { kind: "plan" },
  loadingPlans: { kind: "loadingPlans" },
  creating: { kind: "creating" },
  uncertain: { kind: "uncertain", name: "sirinvpn-01", checking: false, checked: false, found: null },
  uncertainChecking: { kind: "uncertain", name: "sirinvpn-01", checking: true, checked: false, found: null },
  uncertainFound: { kind: "uncertain", name: "sirinvpn-01", checking: false, checked: false, found: created },
  waiting: { kind: "waiting", created },
  failed: { kind: "failed", created, deleting: false },
  failedDeleting: { kind: "failed", created, deleting: true },
  install: { kind: "install", created, ready, deleting: false },
  installDeleting: { kind: "install", created, ready, deleting: true },
  kept: { kind: "kept", created },
  deleted: { kind: "deleted", created },
};
const events: Record<HetznerEvent["type"], HetznerEvent> = {
  loadPlans: { type: "loadPlans" }, plansDone: { type: "plansDone" }, create: { type: "create" }, createFailed: { type: "createFailed" },
  createUncertain: { type: "createUncertain", name: "sirinvpn-01" }, check: { type: "check" }, checked: { type: "checked", found: null },
  checkFailed: { type: "checkFailed" }, absent: { type: "absent" }, wait: { type: "wait", created }, ready: { type: "ready", ready },
  waitFailed: { type: "waitFailed" }, keep: { type: "keep" }, delete: { type: "delete" }, deleted: { type: "deleted" },
  deleteFailed: { type: "deleteFailed" }, startOver: { type: "startOver" },
};
// Every (event, state) pair that changes state, with the result; all others must be ignored.
const transitions: Record<HetznerEvent["type"], Partial<Record<keyof typeof states, HetznerState>>> = {
  loadPlans: { plan: states.loadingPlans },
  plansDone: { loadingPlans: states.plan },
  create: { plan: states.creating },
  createFailed: { creating: states.plan },
  createUncertain: { creating: states.uncertain },
  check: { uncertain: states.uncertainChecking, uncertainFound: { ...states.uncertainFound, checking: true } as HetznerState },
  checked: { uncertainChecking: { ...states.uncertain, checked: true } as HetznerState },
  checkFailed: { uncertainChecking: states.uncertain },
  absent: { uncertain: states.plan },
  wait: { creating: states.waiting, failed: states.waiting, uncertainFound: states.waiting },
  ready: { waiting: states.install },
  waitFailed: { waiting: states.failed },
  keep: { failed: states.kept },
  delete: { failed: states.failedDeleting, install: states.installDeleting },
  deleted: { failedDeleting: states.deleted, installDeleting: states.deleted },
  deleteFailed: { failedDeleting: states.failed, installDeleting: states.install },
  startOver: { deleted: states.plan },
};

describe("hetznerReducer", () => {
  it("follows exactly the listed transitions", () => {
    for (const [type, event] of Object.entries(events) as [HetznerEvent["type"], HetznerEvent][])
      for (const [name, state] of Object.entries(states)) {
        const expected = transitions[type][name];
        if (expected) expect(hetznerReducer(state, event), `${type} in ${name}`).toEqual(expected);
        else expect(hetznerReducer(state, event), `${type} in ${name}`).toBe(state);
      }
  });

  it("never offers Create while a server may exist", () => {
    for (const name of ["uncertain", "uncertainChecking", "uncertainFound"])
      expect(hetznerReducer(states[name], events.create)).toBe(states[name]);
    // A check that finds the server keeps it to adopt; "doesn't exist" is then refused.
    const found = hetznerReducer(states.uncertainChecking, { type: "checked", found: created });
    expect(found).toEqual(states.uncertainFound);
    expect(hetznerReducer(found, events.absent)).toBe(found);
  });

  it("marks every state where a server exists or may exist as unresolved", () => {
    expect(Object.fromEntries(Object.entries(states).map(([name, state]) => [name, hetznerUnresolved(state)]))).toEqual({
      plan: false, loadingPlans: false, creating: true, uncertain: true, uncertainChecking: true, uncertainFound: true, waiting: true,
      failed: true, failedDeleting: true, install: true, installDeleting: true, kept: false, deleted: false,
    });
  });
});
