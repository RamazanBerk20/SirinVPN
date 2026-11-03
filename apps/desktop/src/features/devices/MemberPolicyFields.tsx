import { Warning } from "@phosphor-icons/react";
import { WeeklyAccessFields } from "./WeeklyAccessFields";
import { expiryUnix, policyFieldErrors } from "./memberPolicy";
import { Field } from "../../components/ui";
import type { PolicyDraft } from "./memberPolicy";
import { formatDateTime, t } from "../../i18n";

const PERMISSIONS = [
  ["invite_members", "devices.policy.permission.inviteMembers"],
  ["add_own_devices", "devices.policy.permission.addOwnDevices"],
  ["manage_own_peer_communication", "devices.policy.permission.manageMutualAccess"],
  ["manage_own_port_forwards", "devices.policy.permission.managePortForwards"],
] as const;

/** Limits, schedule and permissions, shared by the invite form and the access policy editor. */
export function MemberPolicyFields({ draft, onChange, delegated = false, creating = false }: {
  draft: PolicyDraft; onChange: (draft: PolicyDraft) => void; delegated?: boolean;
  /** A new member has no devices to revoke yet. */
  creating?: boolean;
}) {
  const errors = policyFieldErrors(draft);
  const expires = draft.expires && !errors.expires ? expiryUnix(draft.expires) : null;
  // The field already shows the date in the system's format; repeat it in UTC only when the day differs.
  const sameDay = expires !== null && new Date(expires * 1000).toISOString().slice(0, 10) === draft.expires.slice(0, 10);
  const utc = expires === null ? null : formatDateTime(new Date(expires * 1000), sameDay ? { timeStyle: "short", timeZone: "UTC" } : { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" });
  return <div className="member-policy-fields">
    <fieldset className="policy-group">
      <legend>{t("devices.policy.limits")}</legend>
      <div className="policy-limit-fields">
        <Field error={errors.limit} label={t("devices.policy.deviceLimit")} hint={t(creating ? "devices.policy.deviceLimitHintNew" : "devices.policy.deviceLimitHint")}>
          <input type="number" min={1} max={222} inputMode="numeric" value={draft.limit} onChange={(event) => onChange({ ...draft, limit: event.target.value })} />
        </Field>
        <Field error={errors.expires} label={t("devices.policy.expires")} hint={utc ? t("devices.policy.expiresUtc", { time: utc }) : t("devices.policy.expiresHint")}>
          <input type="datetime-local" value={draft.expires} onChange={(event) => onChange({ ...draft, expires: event.target.value })} />
        </Field>
      </div>
      {expires !== null && expires * 1000 <= Date.now() && <p className="policy-warning" role="status">
        <Warning size={17} weight="fill" /> <span>{t("devices.policy.expiresPast")}</span>
      </p>}
    </fieldset>
    <WeeklyAccessFields value={draft.schedule} error={errors.schedule} onChange={(schedule) => onChange({ ...draft, schedule })} />
    <fieldset className="policy-group">
      <legend>{t("devices.policy.permissions")}</legend>
      {PERMISSIONS.filter(([key]) => !delegated || key !== "invite_members").map(([key, label]) =>
        <label className="preference-checkbox" key={key}>
          <input type="checkbox" checked={draft.policy[key]} onChange={(event) => onChange({ ...draft, policy: { ...draft.policy, [key]: event.target.checked } })} />
          <span>{t(label)}</span>
        </label>,
      )}
    </fieldset>
  </div>;
}
