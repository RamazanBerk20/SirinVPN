import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { api } from "../../api";
import { isAndroid } from "../../platform";
import { errorMessage } from "../../lib/errors";
import type { AppPreferences, PreferencesSnapshot } from "./preferences";

function usePreferencesController() {
  const [snapshot, setSnapshot] = useState<PreferencesSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState("");
  const [changedKey, setChangedKey] = useState<keyof AppPreferences | null>(
    null,
  );
  const inFlight = useRef(false);
  const generation = useRef(0);
  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    const request = ++generation.current;
    setLoading(true);
    try {
      const next = await api.getAppPreferences();
      if (request !== generation.current) return;
      setSnapshot(next);
      setError(null);
    } catch (reason) {
      if (request === generation.current) setError(errorMessage(reason, "App preferences could not be opened."));
    } finally {
      if (request === generation.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);
  useEffect(() => {
    if (!isAndroid) return;
    const resume = () => { if (document.visibilityState === "visible" && !inFlight.current) void refresh(); };
    document.addEventListener("visibilitychange", resume);
    return () => document.removeEventListener("visibilitychange", resume);
  }, [refresh]);
  useEffect(() => {
    if (isAndroid && snapshot?.font_scale !== undefined)
      document.documentElement.dataset.fontScale = snapshot.font_scale >= 1.5 ? "large" : "normal";
    document.documentElement.dataset.motion =
      snapshot?.preferences.animations === false ? "reduced" : "full";
    return () => {
      delete document.documentElement.dataset.motion;
    };
  }, [snapshot?.preferences.animations]);

  const change = async (key: keyof AppPreferences, value: boolean) => {
    if (!snapshot || inFlight.current) return;
    ++generation.current;
    setLoading(false);
    inFlight.current = true;
    setChangedKey(key);
    setSaving(true);
    setError(null);
    setStatus("");
    try {
      if (key === "notifications" && value) {
        const permission = await api.requestNotificationPermission();
        setSnapshot(
          (current) =>
            current && { ...current, notification_permission: permission },
        );
        if (permission !== "granted") {
          throw new Error(
            "Notifications are blocked. Allow SirinVPN in system notification settings, then try again.",
          );
        }
      }
      const saved = await api.setAppPreferences({
        ...snapshot.preferences,
        [key]: value,
      });
      setSnapshot(saved);
      setStatus("Preferences saved.");
    } catch (reason) {
      setError(
        errorMessage(
          reason,
          "The preference could not be saved. Previous settings remain active.",
        ),
      );
    } finally {
      inFlight.current = false;
      setSaving(false);
    }
  };

  const testNotification = async () => {
    if (inFlight.current) return;
    ++generation.current;
    setLoading(false);
    inFlight.current = true;
    setChangedKey(null);
    setSaving(true);
    setError(null);
    setStatus("");
    try {
      await api.testNotification();
      if (isAndroid) setSnapshot(await api.getAppPreferences());
      setStatus(
        "Test notification sent. Your system's notification settings still apply.",
      );
    } catch (reason) {
      setError(errorMessage(reason, "The notification could not be sent."));
    } finally {
      inFlight.current = false;
      setSaving(false);
    }
  };

  return {
    snapshot,
    changedKey,
    loading,
    saving,
    error,
    status,
    refresh,
    change,
    testNotification,
  };
}

const PreferencesContext = createContext<ReturnType<
  typeof usePreferencesController
> | null>(null);

export function PreferencesProvider({ children }: { children: ReactNode }) {
  const model = usePreferencesController();
  return (
    <PreferencesContext.Provider value={model}>
      {children}
    </PreferencesContext.Provider>
  );
}

export function usePreferences() {
  const model = useContext(PreferencesContext);
  if (!model) throw new Error("PreferencesProvider is missing");
  return model;
}
