import * as Dialog from "@radix-ui/react-dialog";
import { ArrowClockwise } from "@phosphor-icons/react";
import { useId, useState } from "react";
import { api } from "../../api";
import { DialogContent } from "../../components/DialogContent";
import { notify } from "../../components/Toasts";
import { Field, InlineError } from "../../components/ui";
import { confirmAction } from "../../lib/confirmAction";
import { errorMessage } from "../../lib/errors";
import type { DevicePair, DeviceSummary, MembershipSnapshot } from "../../types";
import { t } from "../../i18n";

/**
 * One wording for every pair: "A ↔ B (both ways)" or "A → B (one way)", the arrow pointing from the
 * device that starts connections. A member also sees pairs with devices outside their snapshot, unnamed.
 */
export function pairSummaries(snapshot: MembershipSnapshot, deviceId: string) {
  const names = new Map(snapshot.members.flatMap((member) => member.devices.map((device) => [device.id, device.name] as const)));
  const name = (id: string) => names.get(id) ?? t("devices.pairs.otherDevice");
  return (snapshot.device_pairs ?? [])
    .filter((pair) => pair.device_id === deviceId || pair.peer_device_id === deviceId)
    .map((pair) => {
      const peer = pair.device_id === deviceId ? pair.peer_device_id : pair.device_id;
      const text = !pair.one_way
        ? t("devices.pairs.bothWays", { first: name(deviceId), second: name(peer) })
        : t("devices.pairs.oneWay", { from: name(pair.device_id), to: name(pair.peer_device_id) });
      return { pair, peer, text };
    });
}

type Direction = "both" | "starts" | "answers";

export function DevicePairsDialog({ serverId, device, snapshot, candidates, onClose, onSaved }: {
  serverId: string; device: DeviceSummary; snapshot: MembershipSnapshot;
  /** Devices the caller may pair with this one: the VPS needs that authority over both. */
  candidates: DeviceSummary[];
  onClose: () => void; onSaved: () => Promise<void>;
}) {
  const heading = useId(), formId = useId();
  const pairs = pairSummaries(snapshot, device.id);
  const paired = new Set(pairs.map((pair) => pair.peer));
  // A new pair starts with a device that has none yet; picking a paired one replaces its direction.
  const [peer, setPeer] = useState(() => candidates.find((candidate) => !paired.has(candidate.id))?.id ?? candidates[0]?.id ?? "");
  const [direction, setDirection] = useState<Direction>("both");
  const [busy, setBusy] = useState<string | null>(null), [error, setError] = useState<string | null>(null);
  const removable = (pair: DevicePair) => [pair.device_id, pair.peer_device_id].every((id) => id === device.id || candidates.some((candidate) => candidate.id === id));
  const run = async (key: string, change: () => Promise<unknown>, success: string) => {
    setBusy(key); setError(null);
    try {
      await change();
      notify(success);
      await onSaved();
      return true;
    } catch (reason) {
      setError(errorMessage(reason, t("devices.pairs.saveFailed")));
      return false;
    } finally { setBusy(null); }
  };
  const peerName = candidates.find((candidate) => candidate.id === peer)?.name ?? "";
  const add = async () => {
    const done = await run("add", () => direction === "answers"
      ? api.setDevicePair(serverId, peer, device.id, true)
      : api.setDevicePair(serverId, device.id, peer, direction === "starts"), t("devices.notice.pairAdded", { name: peerName }));
    // This render's pair list predates the new pair, so skip the device just paired as well.
    if (done) { setDirection("both"); setPeer(candidates.find((candidate) => !paired.has(candidate.id) && candidate.id !== peer)?.id ?? peer); }
  };
  const remove = async (pair: DevicePair, peerId: string) => {
    const name = candidates.find((candidate) => candidate.id === peerId)?.name ?? t("devices.pairs.otherDevice");
    if (!await confirmAction({
      title: t("devices.confirm.removePair.title", { first: device.name, second: name }),
      message: t("devices.confirm.removePair.message"),
      confirm: t("devices.confirm.removePair.action"),
    })) return;
    await run(`${pair.device_id}:${pair.peer_device_id}`, () => api.removeDevicePair(serverId, pair.device_id, pair.peer_device_id), t("devices.notice.pairRemoved", { name }));
  };
  return <Dialog.Root open onOpenChange={(open) => { if (!open && !busy) onClose(); }}>
    <Dialog.Portal><Dialog.Overlay className="dialog-overlay" /><DialogContent className="dialog-content invitation-dialog"
          heading={<>{t("devices.pairs.title", { name: device.name })}</>}
          description={<>{t("devices.pairs.description")}</>}
          closeDisabled={busy !== null} closeLabel={t("common.action.close")}
          footer={candidates.length > 0 && <button className="primary-button" type="submit" form={formId} disabled={busy !== null || !peer}>
            {busy === "add" && <ArrowClockwise className="spin" size={17} />}{busy === "add" ? t("common.state.saving") : t("devices.pairs.save")}
          </button>}>
      {pairs.length === 0 ? <p className="pair-list-empty">{t("devices.pairs.none")}</p> : <ul className="pair-list">
        {pairs.map(({ pair, peer: peerId, text }) => {
          const key = `${pair.device_id}:${pair.peer_device_id}`;
          return <li className="pair-row" key={key}>
            <span>{text}</span>
            {removable(pair) && <button className="text-button danger-text" disabled={busy !== null} onClick={() => void remove(pair, peerId)}>
              {busy === key && <ArrowClockwise className="spin" size={15} />}{busy === key ? t("devices.pairs.removing") : t("devices.pairs.remove")}
            </button>}
          </li>;
        })}
      </ul>}
      {candidates.length > 0 && <form className="pair-form" id={formId} aria-labelledby={heading} onSubmit={(event) => { event.preventDefault(); void add(); }}>
        <h3 id={heading}>{t("devices.pairs.addHeading")}</h3>
        <Field label={t("devices.pairs.peer")}>
          <select value={peer} onChange={(event) => setPeer(event.target.value)} disabled={busy !== null}>
            {candidates.map((candidate) => <option key={candidate.id} value={candidate.id}>
              {paired.has(candidate.id) ? t("devices.pairs.pairedOption", { name: candidate.name }) : candidate.name}
            </option>)}
          </select>
        </Field>
        <Field label={t("devices.pairs.direction")} hint={t("devices.pairs.directionHint")}>
          <select value={direction} onChange={(event) => setDirection(event.target.value as Direction)} disabled={busy !== null}>
            <option value="both">{t("devices.pairs.option.both")}</option>
            <option value="starts">{t("devices.pairs.option.oneWay", { from: device.name, to: peerName })}</option>
            <option value="answers">{t("devices.pairs.option.oneWay", { from: peerName, to: device.name })}</option>
          </select>
        </Field>
        {paired.has(peer) && <p className="settings-note">{t("devices.pairs.replaces", { name: peerName })}</p>}
        {error && <InlineError message={error} />}
      </form>}
      {candidates.length === 0 && error && <InlineError message={error} />}
    </DialogContent></Dialog.Portal>
  </Dialog.Root>;
}
