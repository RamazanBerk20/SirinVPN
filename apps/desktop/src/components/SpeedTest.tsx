import { useState } from "react";
import { ArrowClockwise, Gauge } from "@phosphor-icons/react";
import { api } from "../api";
import type { SpeedTestResult } from "../types";
import { formatNumber, t } from "../i18n";
import { errorMessage } from "../lib/errors";

const rate = (bits: number) => t("maintenance.speedTest.rate", { value: formatNumber(bits / 1e6, { maximumFractionDigits: 1 }) });
const latency = (micros: number | null) => micros === null ? t("maintenance.speedTest.notMeasured")
  : t("maintenance.speedTest.latency", { value: formatNumber(micros / 1000, { maximumFractionDigits: 1 }) });

/** Tunnel-to-VPS throughput, measured on request. The result lives only in this component. */
export function SpeedTest({ serverId }: { serverId: string }) {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<SpeedTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    setRunning(true); setResult(null); setError(null);
    try { setResult(await api.speedTest(serverId)); }
    catch (reason) { setError(errorMessage(reason, t("maintenance.speedTest.failed"))); }
    finally { setRunning(false); }
  };
  return <section className="diagnostic-group speed-test">
    <h3>{t("maintenance.speedTest.title")}</h3>
    <p className="settings-note">{t("maintenance.speedTest.description")}</p>
    {result && <dl className="result-facts">
      <div><dt>{t("maintenance.speedTest.download")}</dt><dd>{rate(result.download_bits_per_second)}</dd></div>
      <div><dt>{t("maintenance.speedTest.upload")}</dt><dd>{rate(result.upload_bits_per_second)}</dd></div>
      <div><dt>{t("maintenance.speedTest.idleLatency")}</dt><dd>{latency(result.idle_latency_micros)}</dd></div>
      <div><dt>{t("maintenance.speedTest.downloadLatency")}</dt><dd>{latency(result.download_latency_micros)}</dd></div>
      <div><dt>{t("maintenance.speedTest.uploadLatency")}</dt><dd>{latency(result.upload_latency_micros)}</dd></div>
    </dl>}
    {error && <p className="warning-note" role="alert">{error}</p>}
    <button className="secondary-button" type="button" disabled={running} onClick={() => void run()}>
      {running ? <ArrowClockwise className="spin" /> : <Gauge />}
      {running ? t("maintenance.speedTest.running") : result ? t("maintenance.speedTest.again") : t("maintenance.speedTest.run")}
    </button>
  </section>;
}
