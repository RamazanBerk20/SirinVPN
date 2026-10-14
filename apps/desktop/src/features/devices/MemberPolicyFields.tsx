import { WeeklyAccessFields } from "./WeeklyAccessFields";
import { policyFieldErrors } from "./memberPolicy";
import { Field } from "../../components/ui";
import type { PolicyDraft } from "./memberPolicy";
import { t } from "../../i18n";

const PERMISSIONS = [
  ["invite_members", "devices.policy.permission.inviteMembers"],
  ["add_own_devices", "devices.policy.permission.addOwnDevices"],
  ["manage_own_peer_communication", "devices.policy.permission.manageMutualAccess"],
  ["manage_own_port_forwards", "devices.policy.permission.managePortForwards"],
] as const;

export function MemberPolicyFields({ draft, onChange, delegated = false }: {
  draft: PolicyDraft; onChange: (draft: PolicyDraft) => void; delegated?: boolean;
}) {
  const errors = policyFieldErrors(draft);
  return <div className="member-policy-fields">
    <Field error={errors.limit} label={t("devices.policy.deviceLimit")} hint={t("devices.policy.deviceLimitHint")}>
      <input type="number" min={1} max={222} value={draft.limit} onChange={(event) => onChange({ ...draft, limit: event.target.value })} />
    </Field>
    <Field error={errors.expires} label={t("devices.policy.expires")} hint={t("devices.policy.expiresHint")}>
      <input type="datetime-local" value={draft.expires} onChange={(event) => onChange({ ...draft, expires: event.target.value })} />
    </Field>
    <WeeklyAccessFields value={draft.schedule} error={errors.schedule} onChange={(schedule) => onChange({ ...draft, schedule })} />
    {PERMISSIONS.filter(([key]) => !delegated || key !== "invite_members").map(([key, label]) =>
      <label className="preference-checkbox" key={key}>
        <input type="checkbox" checked={draft.policy[key]} onChange={(event) => onChange({ ...draft, policy: { ...draft.policy, [key]: event.target.checked } })} />
        <span>{t(label)}</span>
      </label>,
    )}
  </div>;
}
