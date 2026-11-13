import * as Dialog from "@radix-ui/react-dialog";
import { ArrowClockwise, ArrowRight, Check, CheckCircle, Copy, Key, Warning } from "@phosphor-icons/react";
import { useEffect, useReducer, useState } from "react";
import { personRole, roleDescription, roleLabel } from "../../access";
import { api } from "../../api";
import { DialogBack, DialogContent } from "../../components/DialogContent";
import { Field, InlineError } from "../../components/ui";
import { formatList, t } from "../../i18n";
import { Rich } from "../../i18n/Rich";
import { preferredBackupPath } from "../../lib/backupPaths";
import { copyText } from "../../lib/clipboard";
import { confirmAction } from "../../lib/confirmAction";
import { appError, errorMessage, formatExpiry } from "../../lib/errors";
import { save } from "../../lib/nativeDialog";
import { isAndroid } from "../../platform";
import type { MemberSummary, MembershipSnapshot } from "../../types";
import { SettingsDisclosure } from "../settings/SettingsParts";
import { connectProblem, fixesPersonName, needsDeviceName, startWizard, whoseProblem, wizardReducer, type WizardDraft, type WizardState } from "./addDeviceWizard";
import { InvitationQr } from "./InvitationQr";
import { InvitationShare } from "./InvitationShare";
import { LimitsAndPermissions } from "./LimitsAndPermissions";
import { policyFromDraft } from "./memberPolicy";
import { addDeviceEntry, type Whose } from "./model";
import { deviceNameProblem, personNameProblem, wireguardFileName } from "./names";
import type { DevicesController } from "./useDevicesController";

/** Who the device is for, resolved against the current list. */
function target(draft: WizardDraft, snapshot: MembershipSnapshot, self: MemberSummary | undefined): MemberSummary | null {
  if (draft.whose?.kind === "self") return self ?? null;
  if (draft.whose?.kind === "person") { const id = draft.whose.personId; return snapshot.members.find((person) => person.id === id) ?? null; }
  return null;
}

export function AddDeviceWizard({ controller, snapshot, preset }: { controller: DevicesController; snapshot: MembershipSnapshot; preset: Whose | null }) {
  const { viewer, self } = controller;
  const inherited = viewer.role === "member" ? { ...self?.policy, invite_members: false } : undefined;
  const [state, dispatch] = useReducer(wizardReducer, null, () => startWizard(preset, inherited));
  const [copied, setCopied] = useState<"idle" | "copied" | "failed">("idle");
  const entry = addDeviceEntry(viewer, snapshot);
  const draft = state.draft;
  const person = target(draft, snapshot, self);
  const waiting = state.step === "handover" && state.handover.status === "waiting";

  // The wizard follows the list the page polls; it reads faster while it waits.
  const { setWatching } = controller;
  useEffect(() => { setWatching(waiting); return () => setWatching(false); }, [waiting, setWatching]);
  useEffect(() => { dispatch({ type: "snapshot", snapshot, now: Date.now() }); }, [snapshot]);

  const close = async () => {
    if (state.step === "creating") return;
    if (state.step === "handover" && state.handover.kind === "code" && !state.handover.shared && state.handover.status === "waiting" && !await confirmAction({
      title: t("devices.add.closeUnshared.title"), message: t("devices.add.closeUnshared.message"), confirm: t("devices.add.closeUnshared.action"),
    })) return;
    controller.setOverlay(null);
  };

  const create = async (current: Extract<WizardState, { step: "connect" }>) => {
    const fresh = current.draft;
    const isNew = fresh.whose?.kind === "new";
    const several = isNew && fresh.newPerson.several;
    const caps = viewer.caps;
    dispatch({ type: "create" });
    try {
      if (fresh.method === "wireguard") {
        const result = await api.createWireGuardDevice(controller.serverId, person?.name ?? fresh.newPerson.name.trim(), fresh.deviceName.trim(), person?.id ?? null,
          isNew && caps.policies ? policyFromDraft(fresh.newPerson.policy) : undefined, fresh.wireguardPath || null);
        dispatch({ type: "createdWireGuard", result });
      } else {
        const naming = needsDeviceName(fresh, caps);
        const result = await api.createInvitation(
          controller.serverId,
          person?.name ?? (several ? "" : fresh.newPerson.name.trim()),
          naming ? fresh.deviceName.trim() : "",
          fresh.lifetime,
          person?.id ?? null,
          person ? Boolean(person.administrator) : fresh.newPerson.role === "admin",
          isNew ? (several ? fresh.newPerson.people : 1) : person?.role === "owner" ? 1 : fresh.uses,
          isNew && fresh.newPerson.role === "member" && caps.policies ? policyFromDraft(fresh.newPerson.policy) : undefined,
          caps.recipientNames && !naming,
          fixesPersonName(fresh, caps),
        );
        dispatch({ type: "createdCode", result, snapshot, personId: person?.id ?? null, seesEveryone: viewer.role !== "member" });
      }
      void controller.refresh();
    } catch (reason) {
      if (isNew && appError(reason, ["person_name_taken"]).code === "person_name_taken")
        dispatch({ type: "nameTaken", error: t("common.errorCode.person_name_taken") });
      else dispatch({ type: "failed", error: errorMessage(reason, t(fresh.method === "wireguard" ? "devices.error.wireguard" : "devices.error.createCode")) });
    }
  };

  const heading = state.step === "handover" ? t("devices.add.handover.title")
    : state.step === "whose" ? t("devices.add.whose.title") : t("devices.add.connect.title");
  const forName = draft.whose?.kind === "new" ? (draft.newPerson.several ? t("devices.add.severalPeople") : draft.newPerson.name.trim()) : person?.name ?? "";
  const description = state.step === "whose" ? t("devices.add.whose.description")
    : draft.whose?.kind === "self" ? t("devices.add.forYou") : t("devices.add.forPerson", { name: forName });

  const footer = state.step === "whose" ? <div className="dialog-commit">
    <button className="primary-button" data-testid="wizard-next" disabled={Boolean(whoseProblem(draft))} onClick={() => dispatch({ type: "next" })}>
      {t("devices.add.next")}<ArrowRight className="mirror-rtl" size={16} aria-hidden="true" />
    </button>
  </div> : state.step === "connect" || state.step === "creating" ? <div className="dialog-commit">
    <DialogBack onClick={() => dispatch({ type: "back" })} disabled={state.step === "creating"} />
    <button className="primary-button" data-testid="wizard-create" disabled={state.step === "creating" || Boolean(connectProblem(draft, needsDeviceName(draft, viewer.caps)))}
      onClick={() => { if (state.step === "connect") void create(state); }}>
      {state.step === "creating" ? <ArrowClockwise className="spin" size={18} aria-hidden="true" /> : <Key size={18} aria-hidden="true" />}
      {state.step === "creating" ? t("devices.add.creating") : t(draft.method === "wireguard" ? "devices.add.createWireguard" : "devices.add.createCode")}
    </button>
  </div> : <div className="dialog-commit">
    {state.handover.kind === "code" && state.handover.status === "waiting" && !isAndroid && <button className="secondary-button" onClick={async () => {
      if (state.handover.kind !== "code") return;
      try { await copyText(state.handover.result.code); setCopied("copied"); dispatch({ type: "shared" }); } catch { setCopied("failed"); }
    }}>{copied === "copied" ? <><Check size={16} aria-hidden="true" /> {t("common.action.copied")}</> : <><Copy size={16} aria-hidden="true" /> {t("devices.add.copyCode")}</>}</button>}
    <button className="primary-button" data-testid="wizard-done" onClick={() => void close()}>{t("devices.add.done")}</button>
  </div>;

  return <Dialog.Root open onOpenChange={(open) => { if (!open) void close(); }}>
    <Dialog.Portal>
      <Dialog.Overlay className="dialog-overlay" />
      <DialogContent className={`dialog-content invitation-dialog add-device-wizard${state.step === "handover" ? " invitation-dialog-ready" : ""}`}
        data-testid="add-device-wizard" data-state={state.step === "handover" ? `handover-${state.handover.status}` : state.step}
        heading={heading} description={description} closeDisabled={state.step === "creating"} closeLabel={t("common.action.close")} footer={footer}>
        {state.step === "whose" && <WhoseStep state={state} dispatch={dispatch} controller={controller} snapshot={snapshot} entry={entry} />}
        {(state.step === "connect" || state.step === "creating") && <ConnectStep draft={draft} dispatch={dispatch} controller={controller} person={person}
          error={state.step === "connect" ? state.error : null} disabled={state.step === "creating"} />}
        {state.step === "handover" && <Handover state={state} dispatch={dispatch} person={person} self={draft.whose?.kind === "self"} copyFailed={copied === "failed"} />}
      </DialogContent>
    </Dialog.Portal>
  </Dialog.Root>;
}

type Dispatch = (event: Parameters<typeof wizardReducer>[1]) => void;

function WhoseStep({ state, dispatch, controller, snapshot, entry }: {
  state: Extract<WizardState, { step: "whose" }>; dispatch: Dispatch; controller: DevicesController; snapshot: MembershipSnapshot; entry: ReturnType<typeof addDeviceEntry>;
}) {
  const { draft } = state;
  const whose = draft.whose;
  const person = draft.newPerson;
  const caps = controller.viewer.caps;
  const [pick, setPick] = useState(() => whose?.kind === "person" ? whose.personId : entry.people[0]?.id ?? "");
  const pickable = entry.people;
  return <form className="invite-form" onSubmit={(event) => { event.preventDefault(); dispatch({ type: "next" }); }}>
    <fieldset className="choice-fieldset">
      <legend className="sr-only">{t("devices.add.whose.title")}</legend>
      <div className="condition-choices">
        {entry.mine && <label className="choice-row" data-testid="whose-self">
          <input type="radio" name="whose" checked={whose?.kind === "self"} disabled={Boolean(entry.mine.blocked)} onChange={() => dispatch({ type: "choose", whose: { kind: "self" } })} />
          <span><strong>{t("devices.add.whose.mine")}</strong><small>{entry.mine.blocked ?? t("devices.add.whose.mineHint")}</small></span>
        </label>}
        {pickable.length > 0 && <label className="choice-row" data-testid="whose-person">
          <input type="radio" name="whose" checked={whose?.kind === "person"} onChange={() => dispatch({ type: "choose", whose: { kind: "person", personId: pick } })} />
          <span><strong>{t("devices.add.whose.person")}</strong><small>{t("devices.add.whose.personHint")}</small></span>
        </label>}
        {whose?.kind === "person" && <Field label={t("devices.add.whose.pick")}>
          <select value={pick} onChange={(event) => { setPick(event.target.value); dispatch({ type: "choose", whose: { kind: "person", personId: event.target.value } }); }}>
            {pickable.map((entry) => <option key={entry.id} value={entry.id}>{t("devices.add.whose.option", { name: entry.name, role: roleLabel(personRole(entry)) })}</option>)}
          </select>
        </Field>}
        {entry.roles.length > 0 && <label className="choice-row" data-testid="whose-new">
          <input type="radio" name="whose" checked={whose?.kind === "new"} onChange={() => dispatch({ type: "choose", whose: { kind: "new" } })} />
          <span><strong>{t("devices.add.whose.new")}</strong><small>{t("devices.add.whose.newHint")}</small></span>
        </label>}
      </div>
    </fieldset>
    {whose?.kind === "person" && (() => {
      const chosen = snapshot.members.find((entry) => entry.id === whose.personId);
      return chosen?.role === "owner" && <OwnerWarning />;
    })()}
    {whose?.kind === "self" && controller.viewer.role === "owner" && <OwnerWarning />}
    {whose?.kind === "new" && <div className="new-person">
      {caps.policies && person.role === "member" && <label className="preference-checkbox">
        <input type="checkbox" checked={person.several} onChange={(event) => dispatch({ type: "editPerson", patch: { several: event.target.checked } })} />
        <span>{t("devices.add.new.several")}</span>
      </label>}
      {person.several
        ? <Field label={t("devices.add.new.people")} hint={t("devices.add.new.peopleHint")} error={whoseProblem(draft) === "people" ? t("devices.add.new.peopleInvalid") : undefined}>
          <input type="number" min={2} max={100} inputMode="numeric" value={person.people} onChange={(event) => dispatch({ type: "editPerson", patch: { people: Number(event.target.value) } })} />
        </Field>
        : <Field label={t("devices.add.new.name")} hint={t(caps.renamePerson ? "devices.add.new.nameHintRename" : "devices.add.new.nameHint")} error={person.name && personNameProblem(person.name) ? personNameProblem(person.name)! : state.error ?? undefined}>
          <input value={person.name} maxLength={128} autoComplete="off" data-testid="new-person-name" onChange={(event) => dispatch({ type: "editPerson", patch: { name: event.target.value } })} />
        </Field>}
      {entry.roles.length > 1 && !person.several && <fieldset className="choice-fieldset">
        <legend>{t("devices.role.title")}</legend>
        <div className="condition-choices">
          {entry.roles.map((role) => <label className="choice-row" key={role}>
            <input type="radio" name="new-role" checked={person.role === role} onChange={() => dispatch({ type: "editPerson", patch: { role: role as "member" | "admin" } })} />
            <span><strong>{roleLabel(role)}</strong><small>{roleDescription(role)}</small></span>
          </label>)}
        </div>
      </fieldset>}
      {entry.roles.length === 1 && <p className="role-line"><span className="access-badge member">{roleLabel("member")}</span> <span>{roleDescription("member")}</span></p>}
      {person.role === "member" && caps.policies && <SettingsDisclosure boxed className="access-disclosure member-policy-disclosure" summary={t("devices.policy.title")}>
        <LimitsAndPermissions draft={person.policy} onChange={(policy) => dispatch({ type: "editPerson", patch: { policy } })} delegated={controller.viewer.role === "member"} creating />
      </SettingsDisclosure>}
    </div>}
  </form>;
}

function OwnerWarning() {
  return <div className="invitation-review-owner" role="note">
    <Warning size={18} weight="fill" aria-hidden="true" />
    <p><strong>{t("devices.add.ownerWarningTitle")}</strong> {t("devices.add.ownerWarning")}</p>
  </div>;
}

function ConnectStep({ draft, dispatch, controller, person, error, disabled }: {
  draft: WizardDraft; dispatch: Dispatch; controller: DevicesController; person: MemberSummary | null; error: string | null; disabled: boolean;
}) {
  const caps = controller.viewer.caps;
  const isNew = draft.whose?.kind === "new";
  // A WireGuard configuration can't make an Admin, nor serve several people.
  const wireguard = caps.wireguard && !(isNew && (draft.newPerson.several || draft.newPerson.role === "admin"));
  const naming = needsDeviceName(draft, caps);
  const multiDevice = !isNew && caps.policies && person?.role !== "owner";
  const edit = (patch: Partial<WizardDraft>) => dispatch({ type: "edit", patch });
  const chooseFile = async () => {
    try {
      const selected = await save({ purpose: "wireguard_export", title: t("devices.add.wireguard.file"), defaultPath: await preferredBackupPath(wireguardFileName(draft.deviceName)),
        filters: [{ name: t("devices.add.wireguard.fileType"), extensions: ["conf"] }] });
      if (typeof selected === "string") edit({ wireguardPath: selected });
    } catch { /* The field keeps its value; the picker has its own error display. */ }
  };
  return <form className="invite-form" onSubmit={(event) => event.preventDefault()}>
    <fieldset className="choice-fieldset" disabled={disabled}>
      <legend className="sr-only">{t("devices.add.connect.title")}</legend>
      <div className="condition-choices">
        <label className="choice-row">
          <input type="radio" name="method" checked={draft.method === "app"} onChange={() => edit({ method: "app" })} />
          <span><strong>{t("devices.add.connect.app")}</strong><small>{t("devices.add.connect.appHint")}</small></span>
        </label>
        {wireguard && <label className="choice-row" data-testid="method-wireguard">
          <input type="radio" name="method" checked={draft.method === "wireguard"} onChange={() => edit({ method: "wireguard" })} />
          <span><strong>{t("devices.add.connect.wireguard")}</strong><small>{t("devices.add.connect.wireguardHint")}</small></span>
        </label>}
      </div>
    </fieldset>
    <fieldset className="policy-form-fields" disabled={disabled}>
      {(draft.method === "wireguard" || naming) && <Field label={t("devices.add.deviceName")} hint={draft.method === "app" ? t("devices.add.deviceNameFixed") : undefined}
        error={draft.deviceName && deviceNameProblem(draft.deviceName) ? deviceNameProblem(draft.deviceName)! : undefined}>
        <input value={draft.deviceName} maxLength={128} autoComplete="off" data-testid="device-name" onChange={(event) => edit({ deviceName: event.target.value })} />
      </Field>}
      {draft.method === "app" ? <div className="invite-form-row">
        <Field label={t("devices.add.lifetime")}>
          <select value={draft.lifetime} onChange={(event) => edit({ lifetime: Number(event.target.value) as WizardDraft["lifetime"] })}>
            <option value={3600}>{t("devices.add.hours", { count: 1 })}</option>
            <option value={86400}>{t("devices.add.hours", { count: 24 })}</option>
            <option value={604800}>{t("devices.add.days", { count: 7 })}</option>
          </select>
        </Field>
        {multiDevice && <Field label={t("devices.add.uses")} hint={t("devices.add.usesHint")} error={connectProblem(draft, false) === "uses" ? t("devices.add.usesInvalid") : undefined}>
          <input type="number" min={1} max={100} inputMode="numeric" value={draft.uses} onChange={(event) => edit({ uses: Number(event.target.value) })} />
        </Field>}
      </div> : <Field label={t("devices.add.wireguard.file")} hint={t("devices.add.wireguard.fileHint")}>
        <div className="file-picker-row">
          <input className="mono" value={draft.wireguardPath} readOnly placeholder={t("devices.add.wireguard.noFile")} />
          <button className="secondary-button" type="button" onClick={() => void chooseFile()}>{t("devices.add.wireguard.chooseFile")}</button>
        </div>
      </Field>}
    </fieldset>
    {draft.method === "wireguard" && <p className="settings-note">{t("devices.add.wireguard.limits")}</p>}
    {error && <InlineError message={error} />}
  </form>;
}

function Handover({ state, dispatch, person, self, copyFailed }: {
  state: Extract<WizardState, { step: "handover" }>; dispatch: Dispatch; person: MemberSummary | null; self: boolean; copyFailed: boolean;
}) {
  const handover = state.handover;
  if (handover.kind === "wireguard") return <div className="invitation-result">
    <p>{t("devices.add.wireguard.instruction")}</p>
    <div className="warning-note"><Warning size={18} weight="fill" aria-hidden="true" /><span>{t("devices.add.wireguard.secret")}</span></div>
    <div className="qr-share">
      <InvitationQr source={`data:image/svg+xml;charset=utf-8,${encodeURIComponent(handover.result.qr_svg)}`} kind="wireguard" />
      {handover.path && <small><Rich id="devices.add.wireguard.saved" params={{ path: handover.path }} tags={{ path: (content) => <span className="mono">{content}</span> }} /></small>}
    </div>
    <JoinState status={handover.status} names={handover.status === "joined" ? [handover.deviceName] : []} />
  </div>;
  const name = state.draft.whose?.kind === "new" ? state.draft.newPerson.name.trim() : person?.name ?? "";
  const instruction = self ? t(isAndroid ? "devices.add.code.instructionSelfAndroid" : "devices.add.code.instructionSelf")
    : state.draft.whose?.kind === "new" && state.draft.newPerson.several ? t("devices.add.code.instructionSeveral") : t("devices.add.code.instructionPerson", { name });
  const waiting = handover.status === "waiting";
  return <div className="invitation-result">
    {waiting && <>
      <p>{instruction}</p>
      <div className="invitation-secret-note" role="note">
        <Warning size={20} weight="fill" aria-hidden="true" />
        <div>
          <strong>{t("devices.add.code.once")}</strong>
          <p>{t("devices.add.code.secret", { date: formatExpiry(handover.result.expires_at_unix) })}</p>
        </div>
      </div>
      {copyFailed && <InlineError message={t(isAndroid ? "devices.add.copyFailedAndroid" : "devices.add.copyFailed")} />}
      <InvitationShare invitation={handover.result} onShared={() => dispatch({ type: "shared" })} />
    </>}
    <JoinState status={handover.status} names={handover.joined} />
  </div>;
}

function JoinState({ status, names }: { status: "waiting" | "joined" | "expired" | "cancelled" | "ended"; names: string[] }) {
  const joined = names.length > 0 && (status === "joined" || status === "waiting");
  return <div className="join-state" role="status" aria-live="polite" data-state={status}>
    {status === "waiting" && !joined && <p><ArrowClockwise className="spin" size={17} aria-hidden="true" /> <span>{t("devices.add.state.waiting")}</span></p>}
    {joined && <p><CheckCircle size={18} weight="fill" aria-hidden="true" /> <span>{t("devices.add.state.joined", { name: formatNames(names), count: names.length })}</span></p>}
    {status === "joined" && names.length === 0 && <p><CheckCircle size={18} weight="fill" aria-hidden="true" /> <span>{t("devices.add.state.connected")}</span></p>}
    {status === "expired" && <p><Warning size={17} weight="fill" aria-hidden="true" /> <span>{t("devices.add.state.expired")}</span></p>}
    {status === "cancelled" && <p><Warning size={17} weight="fill" aria-hidden="true" /> <span>{t("devices.add.state.cancelled")}</span></p>}
    {status === "ended" && <p>{t("devices.add.state.ended")}</p>}
  </div>;
}

const formatNames = (names: string[]) => formatList(names);
