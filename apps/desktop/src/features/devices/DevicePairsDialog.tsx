import * as Dialog from "@radix-ui/react-dialog";
import { useState } from "react";
import { api } from "../../api";
import { DialogContent } from "../../components/DialogContent";
import { Field, InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import type { DevicePair, DeviceSummary, MembershipSnapshot } from "../../types";
import { t } from "../../i18n";

/** A member also sees pairs with devices outside their snapshot, without those devices' names. */
export function pairSummaries(snapshot: MembershipSnapshot, deviceId: string) {
  const names = new Map(snapshot.members.flatMap((member) => member.devices.map((device) => [device.id, device.name] as const)));
  return (snapshot.device_pairs ?? [])
    .filter((pair) => pair.device_id === deviceId || pair.peer_device_id === deviceId)
    .map((pair) => {
      const name = names.get(pair.device_id === deviceId ? pair.peer_device_id : pair.device_id) ?? t("devices.pairs.otherDevice");
      const key = !pair.one_way ? "devices.pairs.bothWays" : pair.device_id === deviceId ? "devices.pairs.starts" : "devices.pairs.answers";
      return { pair, text: t(key, { name }) };
    });
}

type Direction = "both" | "starts" | "answers";

export function DevicePairsDialog({ serverId, device, snapshot, candidates, onClose, onSaved }: {
  serverId: string; device: DeviceSummary; snapshot: MembershipSnapshot;
  /** Devices the caller may pair with this one: the VPS needs that authority over both. */
  candidates: DeviceSummary[];
  onClose: () => void; onSaved: () => Promise<void>;
}) {
  const [peer, setPeer] = useState(candidates[0]?.id ?? "");
  const [direction, setDirection] = useState<Direction>("both");
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null);
  const removable = (pair: DevicePair) => [pair.device_id, pair.peer_device_id].every((id) => id === device.id || candidates.some((candidate) => candidate.id === id));
  const run = async (change: () => Promise<unknown>) => {
    setBusy(true); setError(null);
    try { await change(); await onSaved(); }
    catch (reason) { setError(errorMessage(reason, t("devices.pairs.saveFailed"))); }
    finally { setBusy(false); }
  };
  const add = () => run(() => direction === "answers"
    ? api.setDevicePair(serverId, peer, device.id, true)
    : api.setDevicePair(serverId, device.id, peer, direction === "starts"));
  const pairs = pairSummaries(snapshot, device.id);
  return <Dialog.Root open onOpenChange={(open) => { if (!open && !busy) onClose(); }}>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><DialogContent className="dialog-content invitation-dialog"
          heading={<>{t("devices.pairs.title", { name: device.name })}</>}
          description={<>{t("devices.pairs.description")}</>}
          closeDisabled={busy} closeLabel={t("common.action.close")}>
      <div className="port-forward-list">
        {pairs.length === 0 ? <p className="port-forward-empty">{t("devices.pairs.none")}</p> : pairs.map(({ pair, text }) =>
          <div className="device-pair-row" key={`${pair.device_id}:${pair.peer_device_id}`}>
            <span>{text}</span>
            {removable(pair) && <button className="text-button danger-text" disabled={busy}
              onClick={() => void run(() => api.removeDevicePair(serverId, pair.device_id, pair.peer_device_id))}>{t("devices.pairs.remove")}</button>}
          </div>)}
      </div>
      {candidates.length > 0 && <form className="invite-form" onSubmit={(event) => { event.preventDefault(); void add(); }}>
        <Field label={t("devices.pairs.peer")}>
          <select value={peer} onChange={(event) => setPeer(event.target.value)} disabled={busy}>
            {candidates.map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.name}</option>)}
          </select>
        </Field>
        <Field label={t("devices.pairs.direction")} hint={t("devices.pairs.localNetworks")}>
          <select value={direction} onChange={(event) => setDirection(event.target.value as Direction)} disabled={busy}>
            <option value="both">{t("devices.pairs.option.both")}</option>
            <option value="starts">{t("devices.pairs.option.starts", { name: device.name })}</option>
            <option value="answers">{t("devices.pairs.option.answers", { name: device.name })}</option>
          </select>
        </Field>
        <button className="primary-button" type="submit" disabled={busy}>{busy ? t("common.state.saving") : t("devices.pairs.save")}</button>
      </form>}
      {error && <InlineError message={error} />}
    </DialogContent></Dialog.Portal>
  </Dialog.Root>;
}
