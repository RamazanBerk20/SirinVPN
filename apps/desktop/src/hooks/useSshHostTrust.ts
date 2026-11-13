import { useCallback, useEffect, useReducer, useRef } from "react";
import { api } from "../api";
import { t } from "../i18n";
import { hostTrustReducer, initialHostTrust, type InspectedSshHost } from "./sshHostTrustMachine";

export type { InspectedSshHost } from "./sshHostTrustMachine";

export function useSshHostTrust(host: string, port: number, open: boolean) {
  const [state, dispatch] = useReducer(hostTrustReducer, initialHostTrust);
  const latest = useRef(state);
  latest.current = state;
  const target = JSON.stringify([host.trim(), port, open]);
  const current = useRef(target);
  current.current = target;
  // The machine's request number, known before React renders it, so a result can tell it's stale.
  const seqRef = useRef(initialHostTrust.seq);
  const reset = useCallback(() => { seqRef.current += 1; dispatch({ type: "reset" }); }, []);
  useEffect(reset, [target, reset]);
  // Results arriving after unmount must not count.
  useEffect(() => () => { current.current = ""; }, []);

  const inspect = async (): Promise<InspectedSshHost | null> => {
    const seq = ++seqRef.current;
    dispatch({ type: "check" });
    let result;
    try { result = await api.inspectSshHost(host.trim(), port); }
    catch (reason) { dispatch({ type: "checkFailed", seq }); throw reason; }
    if (target !== current.current || !open || seqRef.current !== seq) return null;
    const inspected = { ...result, host: host.trim(), port };
    dispatch({ type: "inspected", seq, inspection: inspected });
    return inspected;
  };

  /** The pinned fingerprint for an operation: a trusted key, or one the user confirmed, remembered first. */
  const accept = async (inspected: InspectedSshHost) => {
    const state = latest.current;
    if (!open || target !== current.current || inspected.host !== host.trim() || inspected.port !== port)
      throw new Error(t("ssh.error.hostChanged"));
    if (inspected.status !== "trusted") {
      if (state.kind !== "confirmed" || state.inspection.fingerprint !== inspected.fingerprint) throw new Error(t("ssh.error.verifyFirst"));
      await api.trustSshHost(inspected.host, inspected.port, inspected.fingerprint);
      if (seqRef.current !== state.seq || target !== current.current) throw new Error(t("ssh.error.hostChanged"));
      dispatch({ type: "trusted", seq: state.seq });
    }
    return inspected.fingerprint;
  };

  const inspection = state.kind === "trusted" || state.kind === "needsConfirmation" || state.kind === "confirmed" ? state.inspection : null;
  return {
    state: state.kind,
    inspection,
    confirmed: state.kind === "confirmed",
    setConfirmed: (confirmed: boolean) => dispatch({ type: "confirm", confirmed }),
    inspect,
    accept,
    reset,
  };
}
