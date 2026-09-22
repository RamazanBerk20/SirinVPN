import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../api";
import { invoke } from "../../platform";
import { errorMessage } from "../../lib/errors";
import {
  defaultConnectionPreferences,
  type ConnectionPreferences,
} from "./connectionPreferences";

const normalize = (value: ConnectionPreferences): ConnectionPreferences => ({
  ...value,
  routing: {
    ...value.routing,
    included_routes: value.routing.included_routes ?? [],
  },
});

/** Explicit saves keep incomplete routing drafts out of the next connection. */
export function useConnectionPreferences(serverId: string | undefined) {
  const [saved, setSaved] = useState<ConnectionPreferences | null>(null);
  const [draft, setDraft] = useState(defaultConnectionPreferences);
  const [routesText, setRoutesText] = useState("");
  const [ready, setReady] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const generation = useRef(0);
  const inFlight = useRef(false);
  const load = useCallback(async () => {
    const request = ++generation.current;
    setReady(false);
    setSaved(null);
    setError(null);
    setNotice("");
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
          errorMessage(
            reason,
            "Saved connection preferences could not be opened.",
          ),
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
  const dirty = ready && JSON.stringify(saved) !== JSON.stringify(edited);
  const change = (patch: Partial<ConnectionPreferences>) => {
    setDraft((value) => ({ ...value, ...patch }));
    setNotice("");
    setError(null);
  };
  const route = (patch: Partial<ConnectionPreferences["routing"]>) => {
    setDraft((value) => ({
      ...value,
      routing: { ...value.routing, ...patch },
    }));
    setNotice("");
    setError(null);
  };
  const save = async () => {
    if (!serverId || !ready || inFlight.current) return;
    const request = generation.current;
    inFlight.current = true;
    setSaving(true);
    setError(null);
    setNotice("");
    try {
      const value = normalize(
        await api.setConnectionPreferences(serverId, edited),
      );
      if (request !== generation.current) return;
      setSaved(value);
      setDraft(value);
      setRoutesText((value.routing.included_routes ?? []).join("\n"));
      setNotice("Connection preferences saved.");
    } catch (reason) {
      if (request === generation.current)
        setError(
          errorMessage(
            reason,
            "Could not save. Previous preferences remain stored.",
          ),
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
    setSaving(true); setError(null); setNotice("");
    try {
      const value = normalize(await invoke<ConnectionPreferences>("android_set_reconnect", { serverId, enabled }));
      if (request !== generation.current) return;
      setSaved(value);
      // This switch saves only its own value, not incomplete routing or transport drafts.
      setDraft(current => ({ ...current, policy: { ...current.policy, automatic_reconnect: value.policy.automatic_reconnect } }));
      setNotice(`Automatic reconnect ${enabled ? "enabled" : "disabled"}.`);
    } catch (reason) {
      if (request === generation.current) setError(errorMessage(reason, "Automatic reconnect could not be changed."));
    } finally {
      inFlight.current = false; setSaving(false);
    }
  };
  const discard = () => {
    if (!saved || saving) return;
    setDraft(saved);
    setRoutesText((saved.routing.included_routes ?? []).join("\n"));
    setError(null);
    setNotice("");
  };
  return {
    saved,
    draft,
    ready,
    saving,
    dirty,
    error,
    notice,
    routesText,
    setRoutesText,
    change,
    route,
    save,
    setReconnect,
    discard,
    reload: load,
  };
}
