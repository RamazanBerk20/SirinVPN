import { ArrowClockwise, DeviceMobileCamera, UserPlus } from "@phosphor-icons/react";
import { useId, useState } from "react";
import { roleLabel } from "../../access";
import { InlineError } from "../../components/ui";
import { t } from "../../i18n";
import { formatExpiry } from "../../lib/errors";
import { api } from "../../api";
import type { ActiveInvitationSummary, MembershipSnapshot } from "../../types";
import { canCancel, codeTitle, type Viewer } from "./model";
import type { DevicesController } from "./useDevicesController";

function codeDetail(code: ActiveInvitationSummary, snapshot: MembershipSnapshot) {
  const person = code.target_member_id ? snapshot.members.find((entry) => entry.id === code.target_member_id) : undefined;
  const role = person?.role === "owner" ? "owner" : (person?.administrator ?? code.administrator) ? "admin" : "member";
  const max = code.max_uses ?? 1;
  const uses = max <= 1 ? t("devices.codes.singleUse") : t("devices.codes.usesLeft", { count: code.uses_remaining ?? max, max });
  return t("devices.codes.row", { role: roleLabel(role), uses, date: formatExpiry(code.expires_at_unix) });
}

export function cancelCodeChange(controller: DevicesController, code: ActiveInvitationSummary, snapshot: MembershipSnapshot) {
  return controller.change({
    key: `code:${code.id}`,
    confirm: {
      title: t("devices.confirm.cancelCode.title", { name: codeTitle(code, snapshot.members) }),
      message: t("devices.confirm.cancelCode.message"),
      confirm: t("devices.confirm.cancelCode.action"),
    },
    send: () => api.cancelInvitation(controller.serverId, code.id),
    success: t("devices.notice.codeCancelled"),
    failure: t("devices.error.cancelCode"),
  });
}

/** "Waiting to join": every code that hasn't been used up, expired or been cancelled. */
export function JoinCodes({ codes, snapshot, viewer, controller, heading = true }: {
  codes: ActiveInvitationSummary[]; snapshot: MembershipSnapshot; viewer: Viewer; controller: DevicesController; heading?: boolean;
}) {
  const id = useId();
  const [failure, setFailure] = useState<{ id: string; message: string } | null>(null);
  if (codes.length === 0) return null;
  const cancel = async (code: ActiveInvitationSummary) => {
    setFailure(null);
    const error = await cancelCodeChange(controller, code, snapshot);
    if (error) setFailure({ id: code.id, message: error });
  };
  return (
    <section className="invitations-section" aria-labelledby={heading ? id : undefined} aria-label={heading ? undefined : t("devices.codes.title", { count: codes.length })}>
      {heading && <h3 id={id}>{t("devices.codes.title", { count: codes.length })}</h3>}
      <ul className="invitation-items">
        {codes.map((code) => {
          const Icon = code.target_member_id ? DeviceMobileCamera : UserPlus;
          const busy = controller.pending === `code:${code.id}`;
          return (
            <li className="invitation-item" key={code.id}>
              <div className="invitation-item-main">
                <span className="invitation-item-icon" aria-hidden="true"><Icon size={19} /></span>
                <span className="invitation-item-copy">
                  <strong>{codeTitle(code, snapshot.members)}</strong>
                  <small>{codeDetail(code, snapshot)}</small>
                </span>
                {controller.editable && canCancel(viewer, code, snapshot) && (
                  <button className="text-button danger-text" data-testid="cancel-code" disabled={controller.pending !== null} onClick={() => void cancel(code)}>
                    {busy && <ArrowClockwise className="spin" size={15} aria-hidden="true" />}
                    {busy ? t("devices.codes.cancelling") : t("devices.codes.cancel")}
                  </button>
                )}
              </div>
              {failure?.id === code.id && <InlineError message={failure.message} />}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
