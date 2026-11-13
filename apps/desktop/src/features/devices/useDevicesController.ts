import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import { personRole, type Role } from "../../access";
import { api } from "../../api";
import { notify } from "../../components/Toasts";
import { t } from "../../i18n";
import { confirmAction, type Confirmation } from "../../lib/confirmAction";
import { errorMessage } from "../../lib/errors";
import { isAndroid } from "../../platform";
import type { MembershipSnapshot, ServerProfile } from "../../types";
import { rememberMembership, savedMembership } from "./membershipCache";
import { pageReducer, selfPerson, snapshotOf, type Capabilities, type Overlay, type PageState, type Viewer } from "./model";

export interface DevicesProps {
  profile: Pick<ServerProfile, "id" | "name" | "device_id">;
  connected: boolean;
  /** The caller's role from the server status; the list overrides it once read. */
  accessLevel: Role;
  /** Ownership moved: the workspace re-reads this device's role. */
  onAccessChanged: () => Promise<void>;
}

const NO_CAPS: Capabilities = {
  lifecycle: false, policies: false, recipientNames: false, namedCodes: false, renamePerson: false, adminOwnDevices: false,
  wireguard: false, subnetRoutes: false, devicePairs: false, portForwards: false,
};

/** A change to run: optionally confirmed, then sent; its answer replaces the list. */
export interface Change {
  /** What is busy while it runs, e.g. "person:<id>" or "device:<id>". */
  key: string;
  confirm?: Confirmation;
  send: () => Promise<MembershipSnapshot | void>;
  success: string;
  failure: string;
  /** Reads a coded rejection first: a string or null replaces the shown error, undefined keeps it. */
  onError?: (reason: unknown) => string | null | undefined;
}

export function useDevicesController({ profile, connected, accessLevel, onAccessChanged }: DevicesProps) {
  const cacheKey = `${profile.id}:${profile.device_id ?? ""}`;
  const [page, dispatch] = useReducer(pageReducer, null, (): PageState =>
    pageReducer({ kind: "loading" }, connected ? { type: "refreshing" } : { type: "disconnected", saved: savedMembership(cacheKey) }));
  const [overlay, setOverlay] = useState<Overlay>(null);
  const [pending, setPending] = useState<string | null>(null);
  /** Faster reads while the add-device wizard waits for a device to join. */
  const [watching, setWatching] = useState(false);
  // Requests belong to one server and one tunnel. A failed read doesn't end that scope, so a
  // confirmation that is still open survives a flaky poll.
  const scope = useRef(0);
  const read = useRef(0);
  useEffect(() => { scope.current += 1; setPending(null); }, [cacheKey, connected]);

  const refresh = useCallback(async () => {
    const request = ++read.current;
    if (!connected) { dispatch({ type: "disconnected", saved: savedMembership(cacheKey) }); return; }
    dispatch({ type: "refreshing" });
    const [configuration, membership] = await Promise.allSettled([api.serverConfiguration(profile.id), api.membership(profile.id)]);
    if (request !== read.current) return;
    if (configuration.status === "fulfilled" && membership.status === "fulfilled") {
      rememberMembership(cacheKey, membership.value);
      dispatch({ type: "loaded", snapshot: membership.value, configuration: configuration.value, android: isAndroid, at: Date.now() });
      return;
    }
    const error = membership.status === "rejected"
      ? errorMessage(membership.reason, t("devices.error.load"))
      : errorMessage(configuration.status === "rejected" ? configuration.reason : null, t("devices.error.features"));
    dispatch({ type: "failed", error, at: Date.now(),
      configuration: configuration.status === "fulfilled" ? configuration.value : undefined,
      snapshot: membership.status === "fulfilled" ? membership.value : undefined });
  }, [connected, profile.id, cacheKey]);

  useEffect(() => {
    let active = true;
    let timer: number | undefined;
    const poll = async () => {
      if (!document.hidden) await refresh();
      if (active && connected) timer = window.setTimeout(() => void poll(), watching ? 3_000 : 10_000);
    };
    void poll();
    return () => { active = false; read.current += 1; window.clearTimeout(timer); };
  }, [connected, refresh, watching]);

  const snapshot = snapshotOf(page);
  const self = snapshot ? selfPerson(snapshot, profile.device_id) : undefined;
  // Right after an ownership transfer the list knows this device's new role before the status does.
  const role: Role = page.kind === "ready" && self ? personRole(self) : accessLevel;
  const viewer: Viewer = { role, selfId: self?.id, currentDeviceId: profile.device_id, caps: page.kind === "ready" ? page.caps : NO_CAPS };
  const editable = page.kind === "ready";

  const accept = (next: MembershipSnapshot) => {
    rememberMembership(cacheKey, next);
    dispatch({ type: "changed", snapshot: next, at: Date.now() });
  };

  /** Resolves to the error to show beside the control, or null when done (or declined). */
  const change = async ({ key, confirm, send, success, failure, onError }: Change): Promise<string | null> => {
    if (!editable || pending) return null;
    const at = scope.current;
    if (confirm && !await confirmAction(confirm)) return null;
    if (at !== scope.current) {
      notify(t("devices.notice.abandoned"), "error");
      return null;
    }
    setPending(key);
    try {
      const next = await send();
      if (at !== scope.current) return null;
      if (next) accept(next); else void refresh();
      notify(success);
      return null;
    } catch (reason) {
      if (at !== scope.current) return null;
      const handled = onError?.(reason);
      return handled !== undefined ? handled : errorMessage(reason, failure);
    } finally {
      if (at === scope.current) setPending(null);
    }
  };

  return {
    page, snapshot, viewer, self, editable, pending, overlay, setOverlay, refresh, change, accept,
    setWatching, onAccessChanged, serverId: profile.id, serverName: profile.name, currentDeviceId: profile.device_id,
  };
}

export type DevicesController = ReturnType<typeof useDevicesController>;
