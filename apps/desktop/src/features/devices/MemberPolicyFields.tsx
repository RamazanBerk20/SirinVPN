import { WeeklyAccessFields } from "./WeeklyAccessFields";
import { policyFieldErrors } from "./memberPolicy";
import { Field } from "../../components/ui";
import type { PolicyDraft } from "./memberPolicy";

export function MemberPolicyFields({ draft, onChange, delegated = false }: {
  draft: PolicyDraft; onChange: (draft: PolicyDraft) => void; delegated?: boolean;
}) {
  const errors = policyFieldErrors(draft);
  return <div className="member-policy-fields">
    <Field error={errors.limit} label="Device limit" hint="Leave empty for no member-specific limit. Existing excess devices must be revoked before reducing the limit.">
      <input type="number" min={1} max={222} value={draft.limit} onChange={(event) => onChange({ ...draft, limit: event.target.value })} />
    </Field>
    <Field error={errors.expires} label="Access expires (UTC)" hint="Leave empty for no expiration. Expiration stops VPN and management access.">
      <input type="datetime-local" value={draft.expires} onChange={(event) => onChange({ ...draft, expires: event.target.value })} />
    </Field>
    <WeeklyAccessFields value={draft.schedule} error={errors.schedule} onChange={(schedule) => onChange({ ...draft, schedule })} />
    {([
      ["invite_members", "Invite ordinary members"],
      ["add_own_devices", "Add devices to their own membership"],
      ["manage_own_peer_communication", "Manage peer access for their devices"],
      ["manage_own_port_forwards", "Manage public port forwarding to their devices"],
    ] as const).filter(([key]) => !delegated || key !== "invite_members").map(([key, label]) =>
      <label className="preference-checkbox" key={key}>
        <input type="checkbox" checked={draft.policy[key]} onChange={(event) => onChange({ ...draft, policy: { ...draft.policy, [key]: event.target.checked } })} />
        <span>{label}</span>
      </label>,
    )}
  </div>;
}
