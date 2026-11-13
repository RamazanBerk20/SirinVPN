import { useCallback, useReducer, useState } from "react";
import { api, type PlanServerOperationInput } from "../api";
import { t } from "../i18n";
import { errorMessage } from "../lib/errors";
import type { SshCredentials } from "../types";
import { useSshHostTrust, type InspectedSshHost } from "./useSshHostTrust";
import { useSshLogin } from "./useSshLogin";
import { initialSshOperation, operationView, sshOperationReducer, type SshOperationState } from "./sshOperationMachine";

/** Login, host trust and the operation steps shared by every SSH maintenance dialog. */
export function useSshOperation<R>(host: string, open: boolean, loginActive = open) {
  const login = useSshLogin(host, loginActive);
  const trust = useSshHostTrust(host, Number(login.port), open);
  const [state, dispatch] = useReducer(sshOperationReducer<R>, initialSshOperation as SshOperationState<R>);
  // The task's own rejection, for failures shown with their code (ServerChangeFailure).
  const [failure, setFailure] = useState<unknown>(null);
  const { clearSecrets } = login;
  const resetTrust = trust.reset;
  const reset = useCallback(() => { clearSecrets(); resetTrust(); dispatch({ type: "reset" }); }, [clearSecrets, resetTrust]);

  /** Reads the host key: a trusted key goes on to `onTrusted`, any other asks the user to confirm it. */
  const verify = async (unreachable: string, onTrusted: (inspection: InspectedSshHost) => Promise<void> | void) => {
    dispatch({ type: "verify" });
    setFailure(null);
    try {
      const checked = await trust.inspect();
      if (!checked) { dispatch({ type: "back" }); return; }
      if (checked.status === "trusted") await onTrusted(checked);
      else dispatch({ type: "confirmHost" });
    } catch (reason) {
      dispatch({ type: "failed", error: errorMessage(reason, unreachable) });
    }
  };

  /**
   * Pins the key and runs the task with the login. Only once the task worked is a login the user
   * asked to remember saved, and its secrets cleared. Phase 0 is the key, 1 the task; the task may
   * report later phases. Resolves to the result, or null when the task failed.
   * - `loginWorked`: whether a result proves the login (default: any result does)
   * - `keepSecrets`: the login stays in use after this task (a VPS update session)
   */
  const run = async (
    task: (credentials: SshCredentials, setPhase: (phase: number) => void) => Promise<R>,
    fallback: string,
    { inspection = trust.inspection, onError, loginWorked = () => true, keepSecrets = false }: {
      inspection?: InspectedSshHost | null;
      onError?: (reason: unknown) => void;
      loginWorked?: (result: R) => boolean;
      keepSecrets?: boolean;
    } = {},
  ): Promise<R | null> => {
    if (!inspection) return null;
    dispatch({ type: "run" });
    setFailure(null);
    try {
      const fingerprint = await trust.accept(inspection);
      dispatch({ type: "phase", phase: 1 });
      const { credentials, save } = login.prepare(fingerprint);
      const result = await task(credentials, phase => dispatch({ type: "phase", phase }));
      if (loginWorked(result)) await save();
      if (!keepSecrets) login.clearSecrets();
      dispatch({ type: "succeeded", result });
      return result;
    } catch (reason) {
      trust.setConfirmed(false);
      onError?.(reason);
      setFailure(reason);
      dispatch({ type: "failed", error: errorMessage(reason, fallback) });
      return null;
    }
  };

  /** Dry run with the current login. Reads the host key if needed; never trusts a new one. */
  const plan = async (input: (credentials: SshCredentials) => PlanServerOperationInput) => {
    const checked = trust.inspection ?? await trust.inspect();
    if (!checked) throw new Error(t("ssh.error.cancelled"));
    if (checked.status !== "trusted" && !trust.confirmed) throw new Error(t("ssh.error.verifyFirst"));
    return api.planServerOperation(input(login.prepare(checked.fingerprint).credentials));
  };

  return {
    login,
    trust,
    state,
    view: operationView(state),
    busy: state.kind === "verifyingHost" || state.kind === "running",
    error: state.kind === "failed" ? state.error : null,
    failure: state.kind === "failed" ? failure : null,
    plan,
    phase: state.kind === "running" ? state.phase : 0,
    result: state.kind === "succeeded" ? state.result : null,
    verify,
    run,
    review: () => dispatch({ type: "review" }),
    back: () => dispatch({ type: "back" }),
    reset,
  };
}
