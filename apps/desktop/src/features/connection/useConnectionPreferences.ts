import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../api";
import { invoke } from "../../platform";
import { errorMessage } from "../../lib/errors";
import { t } from "../../i18n";
import { notify } from "../../components/Toasts";
import { invalidRoutes } from "../../lib/cidr";
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
  const [saved, setSaved] = useState<ConnectionPreferences | null>(null);
  const [draft, setDraft] = useState(defaultConnectionPreferences);
  const [routesText, setRoutesText] = useState("");
  const [ready, setReady] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // MtuSettings knows the profile's IPv6 minimum and reports it here, so Save can refuse an out-of-range draft.
  const [mtuMinimum, setMtuMinimum] = useState(MIN_MTU);
  const generation = useRef(0);
  const inFlight = useRef(false);
  const load = useCallback(async () => {
    const request = ++generation.current;
    setReady(false);
    setSaved(null);
    setError(null);
    setDraft(defaultConnectionPreferences);
    setRoutesText("");
    if (!serverId) return;
    try {
      const value = normalize(await api.getConnectionPreferences(serverId));
      if (request !== generation.current) return;
      setSaved(value);
      setDraft(value);
      setRoutesText((value.routing.included_routes ?? []).join("\n"));
      setReady(true);
    } catch (reason) {
      if (request === generation.current)
        setError(
          errorMessage(reason, t("connection.preferences.loadError")),
        );
    }
  }, [serverId]);
  useEffect(() => {
    void load();
    return () => {
      ++generation.current;
    };
  }, [load]);

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
  const change = (patch: Partial<ConnectionPreferences>) => {
    setDraft((value) => ({ ...value, ...patch }));
    setError(null);
  };
  const route = (patch: Partial<ConnectionPreferences["routing"]>) => {
    setDraft((value) => ({
      ...value,
      routing: { ...value.routing, ...patch },
    }));
    setError(null);
  };
  const save = async () => {
    if (!serverId || !ready || inFlight.current || badRoutes.length || mtuInvalid) return;
    const request = generation.current;
    inFlight.current = true;
    setSaving(true);
    setError(null);
    try {
      const value = normalize(
        await api.setConnectionPreferences(serverId, edited),
      );
      if (request !== generation.current) return;
      setSaved(value);
      setDraft(value);
      setRoutesText((value.routing.included_routes ?? []).join("\n"));
      // The save bar disappears with the edits, so the confirmation is a toast.
      notify(t("connection.preferences.saved"));
    } catch (reason) {
      if (request === generation.current)
        setError(
          errorMessage(reason, t("connection.preferences.saveError")),
        );
    } finally {
      inFlight.current = false;
      setSaving(false);
    }
  };
  const setReconnect = async (enabled: boolean) => {
    if (!serverId || !ready || inFlight.current) return;
    const request = generation.current;
    inFlight.current = true;
    setSaving(true); setError(null);
    try {
      const value = normalize(await invoke<ConnectionPreferences>("android_set_reconnect", { serverId, enabled }));
      if (request !== generation.current) return;
      setSaved(value);
      // This switch saves only its own value, not incomplete routing or transport drafts.
      setDraft(current => ({ ...current, policy: { ...current.policy, automatic_reconnect: value.policy.automatic_reconnect } }));
      notify(enabled ? t("connection.preferences.reconnectOn") : t("connection.preferences.reconnectOff"));
    } catch (reason) {
      if (request === generation.current) setError(errorMessage(reason, t("connection.preferences.reconnectError")));
    } finally {
      inFlight.current = false; setSaving(false);
    }
  };
  const discard = () => {
    if (!saved || saving) return;
    setDraft(saved);
    setRoutesText((saved.routing.included_routes ?? []).join("\n"));
    setError(null);
  };
  return {
    saved,
    draft,
    ready,
    saving,
    dirty,
    error,
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
