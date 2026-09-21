import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { SshHostInspection } from "../types";

export interface InspectedSshHost extends SshHostInspection {
  host: string;
  port: number;
}

export function useSshHostTrust(host: string, port: number, open: boolean) {
  const [inspection, setInspection] = useState<InspectedSshHost | null>(null);
  const target = JSON.stringify([host.trim(), port, open]);
  const current = useRef(target);
  current.current = target;
  const generation = useRef(0);
  const reset = useCallback(() => {
    generation.current += 1;
    setInspection(null);
  }, []);
  useEffect(reset, [target, reset]);
  useEffect(
    () => () => {
      generation.current += 1;
    },
    [],
  );

  const inspect = async () => {
    const attempt = ++generation.current;
    const result = await api.inspectSshHost(host.trim(), port);
    if (attempt !== generation.current || target !== current.current || !open)
      return null;
    const inspected = { ...result, host: host.trim(), port };
    setInspection(inspected);
    return inspected;
  };

  const accept = async (inspected: InspectedSshHost, confirmed: boolean) => {
    const attempt = generation.current;
    if (
      !open ||
      target !== current.current ||
      inspected.host !== host.trim() ||
      inspected.port !== port
    ) {
      throw new Error("The SSH destination changed. Check its identity again.");
    }
    if (inspected.status !== "trusted") {
      if (!confirmed) throw new Error("Verify this VPS fingerprint first.");
      await api.trustSshHost(
        inspected.host,
        inspected.port,
        inspected.fingerprint,
      );
      if (attempt !== generation.current || target !== current.current)
        throw new Error(
          "The SSH destination changed. Check its identity again.",
        );
      setInspection({ ...inspected, status: "trusted" });
    }
    return inspected.fingerprint;
  };

  return { inspection, inspect, accept, reset };
}
