import { createContext, useContext, useState, type ReactNode } from "react";
import type { ReleaseUpdateCandidate, ReleaseUpdateChannel } from "../../types";

function useSessionState() {
  const [source, setSource] = useState("");
  const [channel, setChannel] = useState<ReleaseUpdateChannel>("stable");
  const [candidate, setCandidate] = useState<ReleaseUpdateCandidate | null>(null);
  const [installed, setInstalled] = useState(false);
  return { source, setSource, channel, setChannel, candidate, setCandidate, installed, setInstalled };
}
const Session = createContext<ReturnType<typeof useSessionState> | null>(null);
export function ReleaseUpdateSession({ children }: { children: ReactNode }) {
  const state = useSessionState();
  return <Session.Provider value={state}>{children}</Session.Provider>;
}
export function useReleaseUpdateSession() {
  const shared = useContext(Session);
  const isolated = useSessionState();
  return shared ?? isolated;
}
