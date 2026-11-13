import { TransportSetupFields, newTransportDraft, transportDraftIsValid, transportSetupFromDraft } from "./TransportSetupFields";
import { DnsChangeReview } from "../dns/DnsChangeReview";
import { useSshOperation } from "../../hooks/useSshOperation";
import { SshLoginFields } from "./SshLoginFields";
import { ConfirmationRow } from "../../components/ConfirmationRow";
import { RepairSummary } from "./RepairSummary";
import { DialogBack, DialogContent } from "../../components/DialogContent";
import { Busy, OperationProgress, stepsAt } from "../../components/OperationResult";
import * as Dialog from "@radix-ui/react-dialog";
import { GlobeHemisphereWest } from "@phosphor-icons/react";
import { useId, useState } from "react";
import { api } from "../../api";
import { SshHostVerification } from "./SshHostVerification";
import { privateDnsDraftIsValid, privateDnsRecordsFromDraft } from "../../dns";
import { type RepairResult, type ServerProfile, type SshCredentials } from "../../types";
import { OperationPlan, ServerChangeFailure } from "../../components/ServerChange";
import { SplitDnsFields, splitDnsDraftIsValid, withSplitDns } from "../dns/SplitDnsFields";
import { t } from "../../i18n";
import {
  type DnsPolicyChoice,
  type PrivateDnsRecordChoice,
  type Nat64Choice,
  type DnsEndpointDraft,
  newDnsEndpointDrafts,
  dnsDraftIsValid,
  dnsUpstreamFromDraft,
  PrivateDnsRecordFields,
  DnsPolicyFields,
  Nat64Fields,
  nat64PrefixIsValid,
} from "../dns/DnsFields";
import { SettingsDisclosure } from "./SettingsParts";

export function RepairServerDialog({
  profile,
  open,
  onOpenChange,
  disconnected,
  onCompleted,
  onReturnHome,
  intent = "repair",
}: {
  profile: ServerProfile;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  disconnected: boolean;
  onCompleted: () => Promise<void>;
  onReturnHome?: () => void;
  /** "security" is a plain repair that starts with automatic security updates selected. */
  intent?: "repair" | "dns" | "security";
}) {
  const formId = useId();
  const dns = intent === "dns";
  const [securityUpdates, setSecurityUpdates] = useState(intent === "security");
  const op = useSshOperation<RepairResult>(profile.endpoint.host, open);
  const { login, trust, view, busy, error, phase, result } = op;
  const { port } = login;
  const [dnsChoice, setDnsChoice] = useState<DnsPolicyChoice>("preserve");
  const [dnsEndpoints, setDnsEndpoints] =
    useState<DnsEndpointDraft[]>(newDnsEndpointDrafts);
  const [privateDnsChoice, setPrivateDnsChoice] =
    useState<PrivateDnsRecordChoice>("preserve");
  const [privateDnsRecords, setPrivateDnsRecords] = useState("");
  const [splitDns, setSplitDns] = useState("");
  const [nat64Choice, setNat64Choice] = useState<Nat64Choice>("preserve");
  const [nat64Prefix, setNat64Prefix] = useState("");
  const [transport, setTransport] = useState(() => newTransportDraft(profile));

  // The dialog stays mounted: each opening starts afresh, and a restore or endpoint update may
  // have changed the saved transport since the draft was last built.
  const [openedAs, setOpenedAs] = useState<string | null>(null);
  const opening = open ? intent : null;
  if (openedAs !== opening) {
    setOpenedAs(opening);
    if (opening) {
      op.reset();
      setTransport(newTransportDraft(profile));
      setSecurityUpdates(intent === "security");
      setDnsChoice("preserve");
      setDnsEndpoints(newDnsEndpointDrafts());
      setPrivateDnsChoice("preserve");
      setPrivateDnsRecords("");
      setSplitDns("");
      setNat64Choice("preserve");
      setNat64Prefix("");
    }
  }

  const changeOpen = (next: boolean) => {
    if (!next && busy) return;
    onOpenChange(next);
  };

  const transportValid = dns || transportDraftIsValid(transport);
  // The first server setting that needs fixing, named so the footer can point at it.
  const invalidSetting = !dnsDraftIsValid(dnsChoice, dnsEndpoints) ? "dns"
    : dnsChoice !== "preserve" && !splitDnsDraftIsValid(splitDns) ? "split"
    : privateDnsChoice === "replace" && !privateDnsDraftIsValid(privateDnsRecords, false) ? "records"
    : nat64Choice === "replace" && !nat64PrefixIsValid(nat64Prefix) ? "nat64" : null;
  const settingsValid = invalidSetting === null;
  const sshValid = disconnected && login.valid && transportValid && settingsValid;
  // Why the primary action is unavailable, most important first.
  const blocker = !disconnected ? t("vps.common.disconnectFirst")
    : !transportValid ? t("ssh.transport.invalid")
    : invalidSetting ? t(`vps.repair.blocked.${invalidSetting}`)
    : login.missing ?? (view === "confirmHost" && !trust.confirmed ? t("ssh.verify.confirmFirst") : null);

  const updateDnsEndpoint = (
    index: number,
    field: keyof DnsEndpointDraft,
    value: string,
  ) => {
    setDnsEndpoints((current) =>
      current.map((endpoint, endpointIndex) =>
        endpointIndex === index ? { ...endpoint, [field]: value } : endpoint,
      ),
    );
  };

  const inspect = async () => {
    if (!sshValid) return;
    await op.verify(t("vps.common.error.unreachable"), checked => dns ? op.review() : repair(checked));
  };

  const repairInput = (credentials: SshCredentials) => ({
    server_id: profile.id,
    ...credentials,
    confirmed: true,
    transport: dns ? null : transportSetupFromDraft(transport, profile),
    dns_upstream:
      dnsChoice === "preserve"
        ? null
        : withSplitDns(dnsChoice === "dns_over_tls" || dnsChoice === "dns_over_https"
          ? dnsUpstreamFromDraft(dnsChoice, dnsEndpoints)
          : { mode: "recursive" }, splitDns),
    private_dns_records:
      privateDnsChoice === "preserve"
        ? null
        : privateDnsChoice === "clear"
          ? []
          : privateDnsRecordsFromDraft(privateDnsRecords),
    ...(!dns && nat64Choice !== "preserve" && {
      nat64_prefix: nat64Choice === "replace" ? nat64Prefix.trim() : null,
    }),
    enable_security_updates: !dns && securityUpdates,
  });

  const repair = async (checked = trust.inspection) => {
    if (!checked || !sshValid || (checked.status !== "trusted" && !trust.confirmed)) return;
    await op.run(async (credentials, setPhase) => {
      const repaired = await api.repairServer(repairInput(credentials));
      setPhase(2);
      await onCompleted();
      return repaired;
    }, dns ? t("vps.repair.error.dns") : t("vps.repair.error.repair"), { inspection: checked, onError: login.clearSecrets });
  };

  const dnsFields = <>
    <DnsPolicyFields
      choice={dnsChoice}
      endpoints={dnsEndpoints}
      allowPreserve
      onChoiceChange={setDnsChoice}
      onEndpointChange={updateDnsEndpoint}
    />
    <PrivateDnsRecordFields
      choice={privateDnsChoice}
      value={privateDnsRecords}
      allowPreserve
      onChoiceChange={setPrivateDnsChoice}
      onValueChange={setPrivateDnsRecords}
    />
    {dnsChoice !== "preserve" && <SplitDnsFields value={splitDns} onChange={setSplitDns} />}
  </>;
  const primaryLabel = dns ? t("vps.repair.action.review") : t("vps.repair.action.repair");

  return (
    <Dialog.Root open={open} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content remove-server-dialog repair-server-dialog"
          heading={dns ? t("vps.repair.titleDns", { name: profile.name }) : t("vps.repair.title", { name: profile.name })}
          description={view === "succeeded"
            ? dns ? t("vps.repair.titleDoneDns") : t("vps.repair.titleDone")
            : view === "running"
              ? t("vps.repair.description.running")
              : dns ? t("vps.repair.description.dns") : t("vps.repair.description.repair")}
          data-operation="repair" data-flow-state={op.state.kind}
          closeDisabled={busy}
          footerNote={view === "form" || view === "confirmHost" || view === "review" ? busy ? null : blocker : null}
          footer={view === "running" ? null
            : view === "succeeded" ? <button className="primary-button" type="button" onClick={() => { onOpenChange(false); onReturnHome?.(); }}>{t("vps.repair.action.home")}</button>
            : <>
              {view !== "form" && <DialogBack disabled={busy} onClick={op.back} />}
              <button className="secondary-button" type="button" disabled={busy} onClick={() => changeOpen(false)}>{t("common.action.cancel")}</button>
              {view === "form" ? <button className="primary-button" type="submit" form={formId} disabled={!sshValid || busy}>{busy ? <Busy label={t("vps.common.checking")} /> : primaryLabel}</button>
                : <button className="primary-button" type="button" disabled={busy || !sshValid || view === "confirmHost" && !trust.confirmed} onClick={() => { if (dns && view === "confirmHost") op.review(); else void repair(); }}>{dns ? view === "confirmHost" ? t("vps.repair.action.review") : t("vps.repair.action.apply") : t("vps.repair.action.repair")}</button>}
            </>}
        >

          {view === "form" ? (
            <form
              className="uninstall-form"
              id={formId}
              onSubmit={(event) => {
                event.preventDefault();
                void inspect();
              }}
            >
              {/* The failure leads the form, where it is seen without scrolling. */}
              <ServerChangeFailure reason={op.failure} message={error} onResolved={() => void onCompleted()} />
              <fieldset disabled={busy} className="ssh-operation-fields">
                <div className="uninstall-target">
                  <GlobeHemisphereWest size={16} />
                  <code>{profile.endpoint.host}</code>
                </div>
                {dns ? <>
                  {/* DNS is what this flow changes, so it comes first; sign-in is the last step. */}
                  {dnsFields}
                  <h3 className="form-section-title">{t("vps.repair.signIn")}</h3>
                  <SshLoginFields login={login} />
                </> : <>
                  <SshLoginFields login={login} />
                  <ConfirmationRow checked={securityUpdates} onChange={setSecurityUpdates}>
                    <strong>{t("vps.repair.securityUpdates")}</strong>
                    <small>{t("vps.repair.securityUpdatesNote")}</small>
                  </ConfirmationRow>
                  <SettingsDisclosure className="advanced-fields repair-options" summary={t("vps.repair.options")}>
                    <p className="settings-note">{t("vps.repair.optionsNote")}</p>
                    <TransportSetupFields value={transport} onChange={setTransport} existing />
                    {dnsFields}
                    <Nat64Fields choice={nat64Choice} value={nat64Prefix} allowPreserve onChoiceChange={setNat64Choice} onValueChange={setNat64Prefix} />
                  </SettingsDisclosure>
                  <p className="settings-note">{t("vps.repair.note")}</p>
                </>}
              </fieldset>
            </form>
          ) : null}

          {view === "confirmHost" && trust.inspection ? (
            <SshHostVerification
              inspection={trust.inspection}
              confirmed={trust.confirmed}
              onConfirmed={trust.setConfirmed}
            />
          ) : null}

          {view === "review" && <div className="dns-change-review-step">
            <p>{t("vps.repair.reviewTarget", { name: profile.name, address: `${profile.endpoint.host.includes(":") ? `[${profile.endpoint.host}]` : profile.endpoint.host}:${port}` })}</p>
            <DnsChangeReview choice={dnsChoice} endpoints={dnsEndpoints} privateChoice={privateDnsChoice} records={privateDnsRecords} splitDns={splitDns} />
          </div>}

          {(view === "form" || view === "confirmHost" || view === "review") && sshValid && !busy
            ? <OperationPlan load={() => op.plan((credentials) => ({ operation: "repair", ...repairInput(credentials) }))} /> : null}

          {view === "running" ? (
            <OperationProgress title={dns ? t("vps.repair.progressDns") : t("vps.repair.progress")}
              steps={stepsAt([t("vps.common.step.identity"), t(dns ? "vps.repair.stepDns" : "vps.repair.step"), t("vps.common.step.refresh")], phase)} />
          ) : null}

          {result ? (
            <RepairSummary profile={profile} result={result} dnsPreserved={dnsChoice === "preserve"} recordsPreserved={privateDnsChoice === "preserve"} />
          ) : null}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
