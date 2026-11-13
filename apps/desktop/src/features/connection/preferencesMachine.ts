import type { ConnectionPreferences } from "./connectionPreferences";

/** What the editor shows once the saved preferences are known. */
export interface PreferenceEditor { saved: ConnectionPreferences; draft: ConnectionPreferences; routesText: string }

/** The preferences editor. `request` numbers a load or save; an answer for another request is dropped. */
export type PreferencesState =
  | { state: "loading"; request: number }
  | { state: "loadFailed"; request: number; message: string }
  | ({ state: "editing" } & PreferenceEditor)
  | ({ state: "saving"; request: number; only: "all" | "reconnect" } & PreferenceEditor)
  | ({ state: "saveFailed"; message: string } & PreferenceEditor);

export type PreferencesAction =
  | { type: "load"; request: number }
  | { type: "loaded"; request: number; value: ConnectionPreferences }
  | { type: "failed"; request: number; message: string }
  | { type: "edit"; draft?: (draft: ConnectionPreferences) => ConnectionPreferences; routesText?: string }
  | { type: "discard" }
  /** `reconnect` saves only the Android reconnect switch and keeps the rest of the draft. */
  | { type: "save"; request: number; only: "all" | "reconnect" }
  | { type: "saved"; request: number; value: ConnectionPreferences };

const routesOf = (value: ConnectionPreferences) => (value.routing.included_routes ?? []).join("\n");
const fresh = (value: ConnectionPreferences): PreferencesState => ({ state: "editing", saved: value, draft: value, routesText: routesOf(value) });
const editor = ({ saved, draft, routesText }: PreferenceEditor): PreferenceEditor => ({ saved, draft, routesText });

export function preferencesReducer(state: PreferencesState, action: PreferencesAction): PreferencesState {
  switch (action.type) {
    case "load": return { state: "loading", request: action.request };
    case "loaded":
      return state.state === "loading" && state.request === action.request ? fresh(action.value) : state;
    case "failed":
      if (state.state === "loading" && state.request === action.request) return { state: "loadFailed", request: action.request, message: action.message };
      if (state.state === "saving" && state.request === action.request) return { state: "saveFailed", message: action.message, ...editor(state) };
      return state;
    case "edit": {
      if (state.state === "loading" || state.state === "loadFailed") return state;
      const next = { ...editor(state), draft: action.draft ? action.draft(state.draft) : state.draft, routesText: action.routesText ?? state.routesText };
      // An edit clears a failed save; during a save the save's answer replaces the draft (as it always has).
      return state.state === "saving" ? { ...state, ...next } : { state: "editing", ...next };
    }
    case "discard":
      return state.state === "editing" || state.state === "saveFailed" ? fresh(state.saved) : state;
    case "save":
      return state.state === "editing" || state.state === "saveFailed" ? { state: "saving", request: action.request, only: action.only, ...editor(state) } : state;
    case "saved": {
      if (state.state !== "saving" || state.request !== action.request) return state;
      if (state.only === "all") return fresh(action.value);
      const draft = { ...state.draft, policy: { ...state.draft.policy, automatic_reconnect: action.value.policy.automatic_reconnect } };
      return { state: "editing", saved: action.value, draft, routesText: state.routesText };
    }
  }
}
