import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../api";
import { invoke } from "../../platform";
import { errorMessage } from "../../lib/errors";
import { t } from "../../i18n";
import { notify } from "../../components/Toasts";
import { invalidRoutes } from "../../lib/cidr";
import { preferencesReducer, type PreferencesAction, type PreferencesState } from "./preferencesMachine";
import {
  defaultConnectionPreferences,
  MAX_MTU,
  MIN_MTU,
  type ConnectionPreferences,
} from "./connectionPreferences";

const normalize = (value: ConnectionPreferences): ConnectionPreferences => ({
  ...value,
  routing: {
    ...value.routing,
    included_routes: value.routing.included_routes ?? [],
  },
});

// The backend omits unset optional fields while the editor writes explicit nulls; compare them as equal.
// Ranges only count in Selected routes mode: the editor drops them in the other modes, so a profile
// that kept ranges from an earlier mode must not look unsaved.
const comparable = (value: ConnectionPreferences | null) =>
  value &&
  JSON.stringify({
    ...value,
    routing: { ...value.routing, included_routes: value.routing.mode === "selected_routes" ? value.routing.included_routes ?? [] : [] },
    manual_mtu: value.manual_mtu ?? undefined,
    android_applications: value.android_applications ?? undefined,
  });

/** Explicit saves keep incomplete routing drafts out of the next connection. */
export function useConnectionPreferences(serverId: string | undefined) {
  const [machine, setMachine] = useState<PreferencesState>({ state: "loading", request: 0 });
  // Mirrors `machine` synchronously, so a second click in the same tick sees the save already running.
  const current = useRef(machine);
  const send = useCallback((action: PreferencesAction) => {
    const next = preferencesReducer(current.current, action);
    if (next === current.current) return;
    current.current = next;
    setMachine(next);
  }, []);
  // MtuSettings knows the profile's IPv6 minimum and reports it here, so Save can refuse an out-of-range draft.
  const [mtuMinimum, setMtuMinimum] = useState(MIN_MTU);
  const requests = useRef(0);
  const load = useCallback(async () => {
    const request = ++requests.current;
    send({ type: "load", request });
    if (!serverId) return;
    try {
      send({ type: "loaded", request, value: normalize(await api.getConnectionPreferences(serverId)) });
    } catch (reason) {
      send({ type: "failed", request, message: errorMessage(reason, t("connection.preferences.loadError")) });
    }
  }, [serverId, send]);
  // A newer load's request number drops the answer of the one it replaced.
  useEffect(() => { void load(); }, [load]);

  const loaded = machine.state === "loading" || machine.state === "loadFailed" ? null : machine;
  const ready = loaded !== null;
  const saved = loaded?.saved ?? null;
  const draft = loaded?.draft ?? defaultConnectionPreferences;
  const routesText = loaded?.routesText ?? "";
  const edited: ConnectionPreferences = {
    ...draft,
    routing: {
      ...draft.routing,
      included_routes:
        draft.routing.mode === "selected_routes"
          ? routesText.split(/[\s,]+/).filter(Boolean)
          : [],
    },
  };
  const dirty = ready && comparable(saved) !== comparable(edited);
  // Selected routes needs at least one well-formed range: an empty list would send nothing through the VPN.
  const badRoutes = edited.routing.mode === "selected_routes"
    ? edited.routing.included_routes.length ? invalidRoutes(edited.routing.included_routes) : [""] : [];
  const mtu = draft.manual_mtu ?? null;
  const mtuInvalid = mtu !== null && (!Number.isInteger(mtu) || mtu < mtuMinimum || mtu > MAX_MTU);
  const change = (patch: Partial<ConnectionPreferences>) => send({ type: "edit", draft: (value) => ({ ...value, ...patch }) });
  const route = (patch: Partial<ConnectionPreferences["routing"]>) =>
    send({ type: "edit", draft: (value) => ({ ...value, routing: { ...value.routing, ...patch } }) });
  const setRoutesText = (text: string) => send({ type: "edit", routesText: text });
  const canSave = () => current.current.state === "editing" || current.current.state === "saveFailed";
  const running = (request: number) => current.current.state === "saving" && current.current.request === request;
  const save = async () => {
    if (!serverId || !canSave() || badRoutes.length || mtuInvalid) return;
    const request = ++requests.current;
    send({ type: "save", request, only: "all" });
    try {
      const value = normalize(await api.setConnectionPreferences(serverId, edited));
      if (!running(request)) return;
      send({ type: "saved", request, value });
      // The save bar disappears with the edits, so the confirmation is a toast.
      notify(t("connection.preferences.saved"));
    } catch (reason) {
      send({ type: "failed", request, message: errorMessage(reason, t("connection.preferences.saveError")) });
    }
  };
  const setReconnect = async (enabled: boolean) => {
    if (!serverId || !canSave()) return;
    const request = ++requests.current;
    send({ type: "save", request, only: "reconnect" });
    try {
      // This switch saves only its own value, not incomplete routing or transport drafts.
      const value = normalize(await invoke<ConnectionPreferences>("android_set_reconnect", { serverId, enabled }));
      if (!running(request)) return;
      send({ type: "saved", request, value });
      notify(enabled ? t("connection.preferences.reconnectOn") : t("connection.preferences.reconnectOff"));
    } catch (reason) {
      send({ type: "failed", request, message: errorMessage(reason, t("connection.preferences.reconnectError")) });
    }
  };
  const discard = () => send({ type: "discard" });
  return {
    saved,
    draft,
    ready,
    saving: machine.state === "saving",
    dirty,
    error: machine.state === "loadFailed" || machine.state === "saveFailed" ? machine.message : null,
    /** The editor's state; the fields above are derived from it. */
    state: machine.state,
    routesText,
    setRoutesText,
    /** Ranges that are not canonical CIDR networks; [""] when Selected routes has none. */
    badRoutes,
    /** True while the draft's manual MTU is out of range; Save stays disabled. */
    mtuInvalid,
    setMtuMinimum,
    change,
    route,
    save,
    setReconnect,
    discard,
    reload: load,
  };
}
