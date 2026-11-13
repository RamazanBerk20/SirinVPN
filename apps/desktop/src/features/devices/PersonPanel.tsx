import { ArrowClockwise, Crown, Plus, Warning } from "@phosphor-icons/react";
import { useState } from "react";
import { personRole, roleDescription, roleLabel, type Role } from "../../access";
import { api } from "../../api";
import { DialogBack } from "../../components/DialogContent";
import { InlineError } from "../../components/ui";
import { t } from "../../i18n";
import { appError } from "../../lib/errors";
import type { MemberSummary, MembershipSnapshot } from "../../types";
import { cancelCodeChange, JoinCodes } from "./JoinCodes";
import { LimitsAndPermissions } from "./LimitsAndPermissions";
import { policyDraft, policyFromDraft, policyProblems } from "./memberPolicy";
import { codesFor, personPermissions, removalCounts, type Capabilities } from "./model";
import { NameField } from "./NameField";
import { personNameProblem } from "./names";
import { DeviceRows, PersonChips } from "./PersonGroup";
import { PanelSection, SidePanel } from "./SidePanel";
import type { DevicesController } from "./useDevicesController";

/** Codes that a change to this person cancels: codes for them, and codes they created when the server says so. */
export function couplingNote(snapshot: MembershipSnapshot, person: MemberSummary, caps: Capabilities) {
  const count = codesFor(snapshot, person.id).length;
  // Servers with named join codes also report every code's issuer, so their counts are exact even with no codes.
  const issuersKnown = caps.namedCodes || snapshot.active_invitations.some((code) => code.issued_by_member_id !== undefined);
  // An older server doesn't say who created a code; anyone who may create codes may have some.
  const mayHaveCreated = !issuersKnown && (personRole(person) === "admin" || Boolean(person.policy?.invite_members));
  return { count, mayHaveCreated };
}

export function PersonPanel({ controller, snapshot, person, view }: {
  controller: DevicesController; snapshot: MembershipSnapshot; person: MemberSummary; view: "main" | "makeOwner";
}) {
  const { viewer, editable, pending } = controller;
  const close = () => controller.setOverlay(null);
  const can = personPermissions(viewer, person);
  const role = personRole(person);
  const busy = pending !== null;
  const self = person.id === viewer.selfId;
  const heading = self ? t("devices.person.youTitle", { name: person.name }) : person.name;
  const description = t("devices.person.summary", { role: roleLabel(role), count: person.devices.length });
  if (view === "makeOwner" && can.makeOwner && !can.makeOwner.blocked)
    return <SidePanel testId="person-panel" heading={t("devices.owner.title", { name: person.name })} description={roleDescription("owner")} onClose={close} busy={busy}>
      <MakeOwner controller={controller} snapshot={snapshot} person={person} />
    </SidePanel>;
  return <SidePanel testId="person-panel" heading={heading} description={description} onClose={close} busy={busy}>
    {!editable && <p className="settings-note" role="status">{t("devices.panel.readOnly")}</p>}
    <PersonChips person={person} />
    {can.rename && <RenamePerson controller={controller} snapshot={snapshot} person={person} />}
    <RoleSection controller={controller} snapshot={snapshot} person={person} />
    <PanelSection title={t("devices.person.devices", { count: person.devices.length })}>
      {person.devices.length === 0
        ? <p className="member-group-empty">{t(person.suspended ? "devices.person.noDevicesSuspended" : "devices.person.noDevices")}</p>
        : <DeviceRows controller={controller} snapshot={snapshot} person={person} devices={person.devices} />}
      {can.addDevice && <div className="panel-actions">
        <button className="secondary-button" data-testid="add-device-for" disabled={!editable || busy || Boolean(can.addDevice.blocked)}
          onClick={() => controller.setOverlay({ kind: "add", preset: self ? { kind: "self" } : { kind: "person", personId: person.id } })}>
          <Plus size={16} weight="bold" aria-hidden="true" />{self ? t("devices.page.addMine") : t("devices.page.addFor", { name: person.name })}
        </button>
        {can.addDevice.blocked && <p className="settings-note">{can.addDevice.blocked}</p>}
      </div>}
      <JoinCodes codes={codesFor(snapshot, person.id)} snapshot={snapshot} viewer={viewer} controller={controller} />
    </PanelSection>
    {can.limits && <LimitsSection controller={controller} snapshot={snapshot} person={person} />}
    {(can.suspend || can.remove) && <DangerZone controller={controller} snapshot={snapshot} person={person} />}
  </SidePanel>;
}

/** The VPS refuses a rename while a device join code for the person waits; it offers to cancel those first. */
function RenamePerson({ controller, snapshot, person }: { controller: DevicesController; snapshot: MembershipSnapshot; person: MemberSummary }) {
  const { editable, pending } = controller;
  const [blocked, setBlocked] = useState<{ name: string; error: string | null } | null>(null);
  const key = `person:${person.id}`;
  const codes = snapshot.active_invitations.filter((code) => code.target_member_id === person.id);
  const rename = async (name: string, cancelFirst: boolean) => {
    let refused = false;
    const error = await controller.change({
      key,
      send: async () => {
        if (cancelFirst) for (const code of codes) await api.cancelInvitation(controller.serverId, code.id);
        return api.renamePerson(controller.serverId, person.id, name);
      },
      success: t("devices.notice.personRenamed", { name }),
      failure: t("devices.error.renamePerson"),
      onError: (reason) => {
        const code = appError(reason, ["person_has_join_codes", "person_name_taken"]).code;
        // Both are 409s from the VPS: a taken name is the field's problem, open join codes need a choice.
        if (code === "person_name_taken") return t("common.errorCode.person_name_taken");
        if (code !== "person_has_join_codes") return undefined;
        refused = true;
        return null;
      },
    });
    setBlocked(refused ? { name, error: null } : cancelFirst && error ? { name, error } : null);
    return cancelFirst ? null : error;
  };
  return <>
    <NameField label={t("devices.person.name")} value={person.name} problem={personNameProblem} testId="rename-person"
      busy={pending === key} disabled={!editable || pending !== null} onSave={(name) => rename(name, false)} />
    {blocked && <div className="coupling-note" role="status">
      <p><Warning size={17} weight="fill" aria-hidden="true" /> <span>{t("devices.person.renameCodesWaiting", { count: codes.length, name: person.name })}</span></p>
      <button className="primary-button" data-testid="cancel-codes-rename" disabled={!editable || pending !== null}
        onClick={() => void rename(blocked.name, true)}>
        {pending === key && <ArrowClockwise className="spin" size={16} aria-hidden="true" />}{t("devices.person.cancelAndRename", { count: codes.length })}
      </button>
      {blocked.error && <InlineError message={blocked.error} />}
    </div>}
  </>;
}

function RoleSection({ controller, snapshot, person }: { controller: DevicesController; snapshot: MembershipSnapshot; person: MemberSummary }) {
  const { viewer, editable, pending } = controller;
  const can = personPermissions(viewer, person);
  const current = personRole(person);
  const [choice, setChoice] = useState<Role>(current);
  const [error, setError] = useState<string | null>(null);
  const { count, mayHaveCreated } = couplingNote(snapshot, person, controller.viewer.caps);
  const key = `person:${person.id}`;
  const apply = async (cancelFirst: boolean) => {
    setError(null);
    const administrator = choice === "admin";
    const codes = codesFor(snapshot, person.id);
    const cancels = cancelFirst && count > 0;
    const message = administrator
      ? t(cancels ? "devices.confirm.role.toAdminCancels" : "devices.confirm.role.toAdmin", { name: person.name, count })
      : t(cancels ? "devices.confirm.role.toMemberCancels" : "devices.confirm.role.toMember", { name: person.name, count });
    const failure = await controller.change({
      key,
      confirm: { title: t("devices.confirm.role.title", { name: person.name, role: roleLabel(choice) }), message, confirm: t("devices.confirm.role.action") },
      send: async () => {
        // The VPS refuses a role change while a code for this person waits, so it goes first.
        if (cancelFirst) for (const code of codes) await api.cancelInvitation(controller.serverId, code.id);
        return api.updateMemberAccess(controller.serverId, person.id, administrator);
      },
      success: t("devices.notice.roleChanged", { name: person.name, role: roleLabel(choice) }),
      failure: t("devices.error.role"),
    });
    setError(failure);
  };
  if (!can.role) return <PanelSection title={t("devices.role.title")}>
    <p className="role-line"><span className={`access-badge ${current}`}>{roleLabel(current)}</span> <span>{roleDescription(current)}</span></p>
  </PanelSection>;
  return <PanelSection title={t("devices.role.title")}>
    <fieldset className="choice-fieldset" disabled={!editable || pending !== null}>
      <legend className="sr-only">{t("devices.role.title")}</legend>
      <div className="condition-choices">
        {(["member", "admin"] as const).map((value) => <label className="choice-row" key={value}>
          <input type="radio" name={`role-${person.id}`} value={value} checked={choice === value} onChange={() => { setChoice(value); setError(null); }} />
          <span><strong>{roleLabel(value)}</strong><small>{roleDescription(value)}</small></span>
        </label>)}
      </div>
    </fieldset>
    {choice !== current && <div className="coupling-note" role="status">
      {count > 0 && <p><Warning size={17} weight="fill" aria-hidden="true" /> <span>{t("devices.role.codesWaiting", { count, name: person.name })}</span></p>}
      {mayHaveCreated && <p className="settings-note">{t("devices.role.createdCodes", { name: person.name })}</p>}
      <button className="primary-button" data-testid="change-role" disabled={!editable || pending !== null} onClick={() => void apply(count > 0)}>
        {pending === key && <ArrowClockwise className="spin" size={16} aria-hidden="true" />}
        {count > 0 ? t("devices.role.cancelAndChange", { count }) : t("devices.role.change", { role: roleLabel(choice) })}
      </button>
    </div>}
    {error && <InlineError message={error} />}
    {can.makeOwner && <div className="make-owner-entry">
      <p><span className="access-badge owner">{roleLabel("owner")}</span> <span>{roleDescription("owner")}</span></p>
      <button className="secondary-button" data-testid="make-owner" disabled={!editable || pending !== null || Boolean(can.makeOwner.blocked)}
        onClick={() => controller.setOverlay({ kind: "person", personId: person.id, view: "makeOwner" })}>
        <Crown size={16} aria-hidden="true" />{t("devices.owner.open")}
      </button>
      {can.makeOwner.blocked && <p className="settings-note">{can.makeOwner.blocked}</p>}
    </div>}
  </PanelSection>;
}

function LimitsSection({ controller, snapshot, person }: { controller: DevicesController; snapshot: MembershipSnapshot; person: MemberSummary }) {
  const { editable, pending } = controller;
  const [draft, setDraft] = useState(() => policyDraft(person.policy));
  const [error, setError] = useState<string | null>(null);
  const invalid = Object.keys(policyProblems(draft)).length > 0;
  const { count, mayHaveCreated } = couplingNote(snapshot, person, controller.viewer.caps);
  const key = `person:${person.id}`;
  const save = async () => {
    if (invalid) return;
    setError(await controller.change({
      key,
      confirm: count > 0 ? {
        title: t("devices.confirm.limits.title", { name: person.name }),
        message: t("devices.confirm.limits.message", { count }),
        confirm: t("devices.confirm.limits.action"),
      } : undefined,
      send: () => api.updateMemberPolicy(controller.serverId, person.id, policyFromDraft(draft)),
      success: t("devices.notice.limitsSaved", { name: person.name }),
      failure: t("devices.error.limits"),
    }));
  };
  return <PanelSection title={t("devices.policy.title")}>
    <LimitsAndPermissions draft={draft} onChange={(next) => { setDraft(next); setError(null); }} role={personRole(person)} disabled={!editable || pending !== null} />
    <div className="panel-actions">
      <p className="settings-note">{count > 0 ? t("devices.policy.cancelsCodes", { count }) : mayHaveCreated ? t("devices.policy.cancelsCreated", { name: person.name }) : t("devices.policy.appliesToAll")}</p>
      <button className="primary-button" data-testid="save-limits" disabled={!editable || pending !== null || invalid} onClick={() => void save()}>
        {pending === key && <ArrowClockwise className="spin" size={16} aria-hidden="true" />}{pending === key ? t("common.state.saving") : t("devices.policy.save")}
      </button>
    </div>
    {error && <InlineError message={error} />}
  </PanelSection>;
}

function DangerZone({ controller, snapshot, person }: { controller: DevicesController; snapshot: MembershipSnapshot; person: MemberSummary }) {
  const { editable, pending, viewer } = controller;
  const can = personPermissions(viewer, person);
  const [error, setError] = useState<string | null>(null);
  const key = `person:${person.id}`;
  const counts = removalCounts(snapshot, person);
  const suspend = async () => setError(await controller.change({
    key,
    confirm: person.suspended
      ? { title: t("devices.confirm.resume.title", { name: person.name }), message: t("devices.confirm.resume.message"), confirm: t("devices.confirm.resume.action") }
      : { title: t("devices.confirm.suspend.title", { name: person.name }), message: t("devices.confirm.suspend.message", { count: person.devices.length }), confirm: t("devices.confirm.suspend.action") },
    send: () => api.updateMemberSuspension(controller.serverId, person.id, !person.suspended),
    success: t(person.suspended ? "devices.notice.resumed" : "devices.notice.suspended", { name: person.name }),
    failure: t("devices.error.suspension"),
  }));
  const remove = async () => {
    const failure = await controller.change({
      key,
      confirm: {
        title: t("devices.confirm.removePerson.title", { name: person.name }),
        message: t("devices.confirm.removePerson.message", { name: person.name, devices: t("devices.count.devices", { count: counts.devices }),
          forwards: t("devices.count.forwards", { count: counts.forwards }), pairs: t("devices.count.pairs", { count: counts.pairs }), codes: t("devices.count.codes", { count: counts.codes }) }),
        confirm: t("devices.confirm.removePerson.action"),
      },
      send: () => api.revokeMemberDevices(controller.serverId, person.id, true),
      success: t("devices.notice.personRemoved", { name: person.name }),
      failure: t("devices.error.removePerson"),
    });
    setError(failure);
  };
  return <PanelSection title={t("devices.person.dangerZone")} danger>
    {can.suspend && <div className="danger-row">
      <p>{t(person.suspended ? "devices.person.resumeHint" : "devices.person.suspendHint")}</p>
      <button className="secondary-button" data-testid={person.suspended ? "resume-person" : "suspend-person"} disabled={!editable || pending !== null} onClick={() => void suspend()}>
        {t(person.suspended ? "devices.person.resume" : "devices.person.suspend")}
      </button>
    </div>}
    {can.remove && <div className="danger-row">
      <p>{t("devices.person.removeHint", { devices: t("devices.count.devices", { count: counts.devices }), forwards: t("devices.count.forwards", { count: counts.forwards }), pairs: t("devices.count.pairs", { count: counts.pairs }), codes: t("devices.count.codes", { count: counts.codes }) })}</p>
      <button className="primary-button danger-action" data-testid="remove-person" disabled={!editable || pending !== null} onClick={() => void remove()}>
        {t("devices.person.remove")}
      </button>
    </div>}
    {error && <InlineError message={error} />}
  </PanelSection>;
}

/** The Owner chooses which of the person's devices receives ownership. */
function MakeOwner({ controller, snapshot, person }: { controller: DevicesController; snapshot: MembershipSnapshot; person: MemberSummary }) {
  const { editable, pending, viewer } = controller;
  const eligible = person.devices.filter((device) => !device.wireguard_only);
  const [deviceId, setDeviceId] = useState(eligible[0]?.id ?? "");
  const [error, setError] = useState<string | null>(null);
  const owner = snapshot.members.find((entry) => entry.role === "owner");
  // The VPS refuses while a code for the current Owner or for this person waits.
  const blocking = snapshot.active_invitations.filter((code) => code.target_member_id === person.id || (owner && code.target_member_id === owner.id));
  const device = eligible.find((entry) => entry.id === deviceId);
  const transfer = async () => {
    if (!device) return;
    const failure = await controller.change({
      key: `person:${person.id}`,
      confirm: {
        title: t("devices.confirm.makeOwner.title", { name: person.name }),
        message: t("devices.confirm.makeOwner.message", { device: device.name, fingerprint: device.identity_fingerprint ?? device.id }),
        confirm: t("devices.confirm.makeOwner.action"),
      },
      send: () => api.transferOwnership(controller.serverId, device.id),
      success: t("devices.notice.ownerChanged", { name: person.name }),
      failure: t("devices.error.makeOwner"),
    });
    setError(failure);
    if (!failure) { controller.setOverlay(null); await controller.onAccessChanged(); }
  };
  return <div className="make-owner">
    <p className="policy-warning"><Warning size={17} weight="fill" aria-hidden="true" /> <span>{t("devices.owner.effect", { name: person.name })}</span></p>
    <fieldset className="choice-fieldset" disabled={!editable || pending !== null}>
      <legend>{t("devices.owner.device")}</legend>
      <div className="condition-choices">
        {eligible.map((entry) => <label className="choice-row" key={entry.id}>
          <input type="radio" name="owner-device" value={entry.id} checked={deviceId === entry.id} onChange={() => setDeviceId(entry.id)} />
          <span><strong>{entry.name}</strong><small className="mono" dir="ltr">{entry.identity_fingerprint ?? entry.client_tunnel_address}</small></span>
        </label>)}
      </div>
      {person.devices.length > eligible.length && <p className="settings-note">{t("devices.owner.wireguardExcluded")}</p>}
    </fieldset>
    {blocking.length > 0 && <div className="coupling-note">
      <p><Warning size={17} weight="fill" aria-hidden="true" /> <span>{t("devices.owner.codesWaiting", { count: blocking.length })}</span></p>
      {blocking.map((code) => <button key={code.id} className="secondary-button" disabled={!editable || pending !== null}
        onClick={async () => setError(await cancelCodeChange(controller, code, snapshot))}>{t("devices.owner.cancelCode", { name: snapshot.members.find((entry) => entry.id === code.target_member_id)?.name ?? code.member_name })}</button>)}
    </div>}
    {error && <InlineError message={error} />}
    <div className="panel-actions">
      <DialogBack onClick={() => controller.setOverlay({ kind: "person", personId: person.id, view: "main" })} disabled={pending !== null} />
      <button className="primary-button danger-action" data-testid="confirm-make-owner" disabled={!editable || pending !== null || !device || blocking.length > 0 || viewer.role !== "owner"} onClick={() => void transfer()}>
        {pending === `person:${person.id}` && <ArrowClockwise className="spin" size={16} aria-hidden="true" />}{t("devices.owner.confirm", { name: person.name })}
      </button>
    </div>
  </div>;
}
