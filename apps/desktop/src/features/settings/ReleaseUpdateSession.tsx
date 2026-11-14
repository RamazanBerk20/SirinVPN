import { createContext, useContext, useReducer, useState, type ReactNode } from "react";
import type { ReleaseUpdateChannel } from "../../types";
import { initialRelease, releaseReducer } from "./releaseUpdateMachine";
import { installedChannel, rememberedAppReleaseSource } from "./vpsRelease";

function useSessionState() {
  const [source, setSource] = useState(rememberedAppReleaseSource);
  const [channel, setChannel] = useState<ReleaseUpdateChannel>(installedChannel);
  const [state, dispatch] = useReducer(releaseReducer, initialRelease);
  return { source, setSource, channel, setChannel, state, dispatch };
}
const Session = createContext<ReturnType<typeof useSessionState> | null>(null);
/** One update session for the whole app, so a reviewed or installed release survives closing the dialog. */
export function ReleaseUpdateSession({ children }: { children: ReactNode }) {
  const state = useSessionState();
  return <Session.Provider value={state}>{children}</Session.Provider>;
}
/** Without a provider (a dialog rendered alone, as in tests) the dialog keeps its own session. */
export function useReleaseUpdateSession() {
  const shared = useContext(Session);
  const isolated = useSessionState();
  return shared ?? isolated;
}
