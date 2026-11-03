import { useEffect, useRef, useState } from "react";
import { ArrowClockwise, Gauge } from "@phosphor-icons/react";
import { api } from "../api";
import type { SpeedTestResult } from "../types";
import { formatNumber, t } from "../i18n";
import { errorMessage } from "../lib/errors";
import { InlineError } from "./ui";

const rate = (bits: number) => t("maintenance.speedTest.rate", { value: formatNumber(bits / 1e6, { maximumFractionDigits: 1 }) });
const latency = (micros: number | null) => micros === null ? t("maintenance.speedTest.notMeasured")
  : t("maintenance.speedTest.latency", { value: formatNumber(micros / 1000, { maximumFractionDigits: 1 }) });

// The native test reports no progress, so the phase comes from its fixed timing
// (crates/core/src/diagnostics/speed.rs): about 2 s of idle latency, then 8 s each of download and upload.
const TOTAL_SECONDS = 20;
// The VPS allows one test a minute from when a test starts, cancelled or not (COOLDOWN in crates/server/src/speed_test.rs).
const COOLDOWN_MS = 60_000;
export const speedTestPhase = (elapsed: number) => elapsed < 2 ? "idle" : elapsed < 10 ? "download" : elapsed < 18 ? "upload" : "finishing";

/** Tunnel-to-VPS throughput, measured on request. The result lives only in this component. */
export function SpeedTest({ serverId }: { serverId: string }) {
  const [running, setRunning] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [result, setResult] = useState<SpeedTestResult | null>(null);
  const [cancelled, setCancelled] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const section = useRef<HTMLElement>(null);
  const startedAt = useRef(0);
  // After a cancel, when the VPS will take the next test; the Run button waits for it instead of failing.
  const [readyAt, setReadyAt] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (readyAt === null) return;
    const timer = setInterval(() => {
      const current = Date.now();
      setNow(current);
      if (current >= readyAt) setReadyAt(null);
    }, 1000);
    return () => clearInterval(timer);
  }, [readyAt]);
  useEffect(() => {
    if (!running) return;
    // The progress replaces the button: keep it in view, since the test slows the VPN while it runs.
    section.current?.scrollIntoView?.({ block: "nearest" });
    const started = Date.now();
    setElapsed(0);
    const timer = setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 500);
    // Closing the dialog mid-test stops it, since its result would be lost; after a finished test this does nothing.
    return () => { clearInterval(timer); void api.cancelSpeedTest(); };
  }, [running]);
  const run = async () => {
    setRunning(true); setResult(null); setCancelled(false); setError(null); setReadyAt(null);
    startedAt.current = Date.now();
    try {
      const outcome = await api.speedTest(serverId);
      setResult(outcome);
      setCancelled(!outcome);
      if (!outcome) { setNow(Date.now()); setReadyAt(startedAt.current + COOLDOWN_MS); }
    }
    catch (reason) { setError(errorMessage(reason, t("maintenance.speedTest.failed"))); }
    finally { setRunning(false); }
  };
  const phase = speedTestPhase(elapsed);
  const phaseText = t(`settings.speedTest.phase.${phase}`);
  return <section ref={section} className="diagnostic-group speed-test">
    <h3>{t("maintenance.speedTest.title")}</h3>
    <p className="settings-note">{t("maintenance.speedTest.description")}</p>
    {result && <dl className="result-facts">
      <div><dt>{t("maintenance.speedTest.download")}</dt><dd>{rate(result.download_bits_per_second)}</dd></div>
      <div><dt>{t("maintenance.speedTest.upload")}</dt><dd>{rate(result.upload_bits_per_second)}</dd></div>
      <div><dt>{t("maintenance.speedTest.idleLatency")}</dt><dd>{latency(result.idle_latency_micros)}</dd></div>
      <div><dt>{t("maintenance.speedTest.downloadLatency")}</dt><dd>{latency(result.download_latency_micros)}</dd></div>
      <div><dt>{t("maintenance.speedTest.uploadLatency")}</dt><dd>{latency(result.upload_latency_micros)}</dd></div>
    </dl>}
    {running ? <>
      <div className="speed-test-progress" role="status">
        <strong><ArrowClockwise className="spin" size={18} />{t("maintenance.speedTest.running")}</strong>
        <progress max={TOTAL_SECONDS} value={Math.min(elapsed, TOTAL_SECONDS)} aria-label={phaseText} />
        <p>{phase === "finishing" ? t("settings.speedTest.finishingLine", { phase: phaseText })
          : t("settings.speedTest.left", { phase: phaseText, seconds: formatNumber(TOTAL_SECONDS - elapsed) })}</p>
      </div>
      <button className="secondary-button" type="button" onClick={() => void api.cancelSpeedTest()}>{t("settings.speedTest.cancel")}</button>
    </> : error ? <InlineError message={error} onRetry={() => void run()} />
      : <>
        {cancelled && <p className="settings-note" role="status">{readyAt === null ? t("settings.speedTest.cancelled")
          : t("settings.speedTest.cancelledWait", { seconds: formatNumber(Math.max(1, Math.ceil((readyAt - now) / 1000))) })}</p>}
        <button className="secondary-button" type="button" disabled={readyAt !== null} onClick={() => void run()}>
          <Gauge />{result ? t("maintenance.speedTest.again") : t("maintenance.speedTest.run")}
        </button>
      </>}
  </section>;
}
