import { Warning } from "@phosphor-icons/react";
import { Field } from "../../components/ui";
import { t } from "../../i18n";
import type { Role } from "../../access";
import { expiryUnix, policyProblems, type PolicyDraft } from "./memberPolicy";
import { emptyWeek, WeekGrid } from "./WeekGrid";

const PERMISSIONS = [
  ["invite_members", "devices.policy.permission.addPeople"],
  ["add_own_devices", "devices.policy.permission.addOwnDevices"],
  ["manage_own_peer_communication", "devices.policy.permission.deviceToDevice"],
  ["manage_own_port_forwards", "devices.policy.permission.portForwards"],
] as const;

const zone = () => Intl.DateTimeFormat().resolvedOptions().timeZone ?? "";

/**
 * Limits and permissions for one person, shared by the add-device wizard and the person panel.
 * An Admin already adds and manages people, so only their own-device permissions show.
 */
export function LimitsAndPermissions({ draft, onChange, role = "member", delegated = false, creating = false, disabled = false }: {
  draft: PolicyDraft; onChange: (draft: PolicyDraft) => void; role?: Role;
  /** A Member giving someone new at most what they have themselves. */
  delegated?: boolean;
  /** Someone new has no devices to remove before lowering the limit. */
  creating?: boolean;
  disabled?: boolean;
}) {
  const problems = policyProblems(draft);
  const expires = draft.expires && !problems.expires ? expiryUnix(draft.expires) : null;
  const permissions = PERMISSIONS.filter(([key]) => !(key === "invite_members" && (delegated || role === "admin")));
  return <div className="member-policy-fields">
    <fieldset className="policy-group" disabled={disabled}>
      <legend>{t("devices.policy.limits")}</legend>
      <div className="policy-limit-fields">
        <Field error={problems.limit} label={t("devices.policy.deviceLimit")} hint={t(creating ? "devices.policy.deviceLimitHintNew" : "devices.policy.deviceLimitHint")}>
          <input type="number" min={1} max={222} inputMode="numeric" value={draft.limit} onChange={(event) => onChange({ ...draft, limit: event.target.value })} />
        </Field>
        <Field error={problems.expires} label={t("devices.policy.expires")} hint={t("devices.policy.expiresHint")}>
          <input type="datetime-local" value={draft.expires} onChange={(event) => onChange({ ...draft, expires: event.target.value })} />
        </Field>
      </div>
      {expires !== null && expires * 1000 <= Date.now() && <p className="policy-warning" role="status">
        <Warning size={17} weight="fill" aria-hidden="true" /> <span>{t("devices.policy.expiresPast")}</span>
      </p>}
    </fieldset>
    <fieldset className="policy-group weekly-access" disabled={disabled}>
      <legend>{t("devices.hours.title")}</legend>
      <label className="preference-row">
        <span>
          <strong>{t("devices.hours.limit")}</strong>
          <small>{draft.hoursLimited ? t("devices.hours.localTime", { zone: zone() }) : t("devices.hours.allWeek")}</small>
        </span>
        <input type="checkbox" role="switch" aria-label={t("devices.hours.limit")} checked={draft.hoursLimited}
          onChange={(event) => onChange({ ...draft, hoursLimited: event.target.checked, hoursEdited: true,
            hours: draft.hours.some(Boolean) ? draft.hours : emptyWeek() })} />
      </label>
      {draft.hoursLimited && <>
        {draft.hoursInexact && !draft.hoursEdited && <p className="policy-group-note">{t("devices.hours.inexact")}</p>}
        <WeekGrid label={t("devices.hours.title")} cells={draft.hours} disabled={disabled}
          onChange={(hours) => onChange({ ...draft, hours, hoursEdited: true })} />
        {problems.hours && <p className="field-error" role="alert">{problems.hours}</p>}
      </>}
    </fieldset>
    <fieldset className="policy-group" disabled={disabled}>
      <legend>{t("devices.policy.permissions")}</legend>
      {permissions.map(([key, label]) =>
        <label className="preference-checkbox" key={key}>
          <input type="checkbox" checked={draft.policy[key]} onChange={(event) => onChange({ ...draft, policy: { ...draft.policy, [key]: event.target.checked } })} />
          <span>{t(label)}</span>
        </label>,
      )}
    </fieldset>
  </div>;
}
