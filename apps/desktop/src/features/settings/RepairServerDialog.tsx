import { TransportSetupFields, newTransportDraft, transportDraftIsValid, transportSetupFromDraft } from "./TransportSetupFields";
import { DnsChangeReview } from "../dns/DnsChangeReview";
import { useSshLogin } from "../../hooks/useSshLogin";
import { SshLoginFields } from "./SshLoginFields";
import { ConfirmationRow } from "../../components/ConfirmationRow";
import { RepairSummary } from "./RepairSummary";
import { DialogBack, DialogContent } from "../../components/DialogContent";
import { Busy, OperationProgress, stepsAt } from "../../components/OperationResult";
import * as Dialog from "@radix-ui/react-dialog";
import { GlobeHemisphereWest } from "@phosphor-icons/react";
import { useEffect, useId, useState } from "react";
import { api } from "../../api";
import {
  useSshHostTrust,
  type InspectedSshHost,
} from "../../hooks/useSshHostTrust";
import { SshHostVerification } from "./SshHostVerification";
import { privateDnsDraftIsValid, privateDnsRecordsFromDraft } from "../../dns";
import { type RepairResult, type ServerProfile } from "../../types";
import { SplitDnsFields, splitDnsDraftIsValid, withSplitDns } from "../dns/SplitDnsFields";
import { InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
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
  const [step, setStep] = useState<
    "details" | "fingerprint" | "review" | "repairing" | "success"
  >("details");
  // Which step of the running task is under way, for its progress list.
  const [phase, setPhase] = useState(0);
  const login = useSshLogin(profile.endpoint.host, open);
  const { port } = login;
  const trust = useSshHostTrust(profile.endpoint.host, Number(port), open);
  const [confirmed, setConfirmed] = useState(false);
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
  const [result, setResult] = useState<RepairResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const clearSecrets = () => {
    login.clearSecrets();
  };

  useEffect(() => {
    if (open) {
      // The dialog stays mounted; a restore or endpoint update may have changed
      // the saved transport since the draft was last built.
      setTransport(newTransportDraft(profile));
      setSecurityUpdates(intent === "security");
    } else {
      clearSecrets();
      setStep("details");
      trust.reset();
      setConfirmed(false);
      setDnsChoice("preserve");
      setDnsEndpoints(newDnsEndpointDrafts());
      setPrivateDnsChoice("preserve");
      setPrivateDnsRecords("");
      setSplitDns("");
      setNat64Choice("preserve");
      setNat64Prefix("");
      setTransport(newTransportDraft(profile));
      setResult(null);
      setError(null);
      setBusy(false);
    }
  }, [open, intent]);

  const changeOpen = (next: boolean) => {
    if (!next && (busy || step === "repairing")) return;
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
    : login.missing ?? (step === "fingerprint" && !confirmed ? t("ssh.verify.confirmFirst") : null);

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
    setBusy(true);
    setError(null);
    try {
      const checked = await trust.inspect();
      if (!checked) return;
      setConfirmed(false);
      if (checked.status === "trusted") {
        if (dns) setStep("review");
        else await repair(checked);
      } else {
        setStep("fingerprint");
      }
    } catch (reason) {
      setError(errorMessage(reason, t("vps.common.error.unreachable")));
    } finally {
      setBusy(false);
    }
  };

  const repair = async (
    checked: InspectedSshHost | null = trust.inspection,
  ) => {
    if (!checked || !sshValid || (checked.status !== "trusted" && !confirmed))
      return;
    setStep("repairing");
    setPhase(0);
    setBusy(true);
    setError(null);
    try {
      const fingerprint = await trust.accept(checked, confirmed);
      setPhase(1);
      const repaired = await api.repairServer({
        server_id: profile.id,
        ...(await login.prepare(fingerprint)),
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
      clearSecrets();
      setPhase(2);
      await onCompleted();
      setResult(repaired);
      setStep("success");
    } catch (reason) {
      clearSecrets();
      setConfirmed(false);
      setStep("details");
      setError(
        errorMessage(reason, dns ? t("vps.repair.error.dns") : t("vps.repair.error.repair")),
      );
    } finally {
      setBusy(false);
    }
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
          description={step === "success"
            ? dns ? t("vps.repair.titleDoneDns") : t("vps.repair.titleDone")
            : step === "repairing"
              ? t("vps.repair.description.running")
              : dns ? t("vps.repair.description.dns") : t("vps.repair.description.repair")}
          closeDisabled={busy || step === "repairing"}
          footerNote={step === "details" || step === "fingerprint" || step === "review" ? busy ? null : blocker : null}
          footer={step === "repairing" ? null
            : step === "success" ? <button className="primary-button" type="button" onClick={() => { onOpenChange(false); onReturnHome?.(); }}>{t("vps.repair.action.home")}</button>
            : <>
              {step !== "details" && <DialogBack disabled={busy} onClick={() => setStep("details")} />}
              <button className="secondary-button" type="button" disabled={busy} onClick={() => changeOpen(false)}>{t("common.action.cancel")}</button>
              {step === "details" ? <button className="primary-button" type="submit" form={formId} disabled={!sshValid || busy}>{busy ? <Busy label={t("vps.common.checking")} /> : primaryLabel}</button>
                : <button className="primary-button" type="button" disabled={busy || !sshValid || step === "fingerprint" && !confirmed} onClick={() => { if (dns && step === "fingerprint") setStep("review"); else void repair(); }}>{dns ? step === "fingerprint" ? t("vps.repair.action.review") : t("vps.repair.action.apply") : t("vps.repair.action.repair")}</button>}
            </>}
        >

          {step === "details" ? (
            <form
              className="uninstall-form"
              id={formId}
              onSubmit={(event) => {
                event.preventDefault();
                void inspect();
              }}
            >
              {/* The failure leads the form, where it is seen without scrolling. */}
              {error ? <InlineError message={error} /> : null}
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

          {step === "fingerprint" && trust.inspection ? (
            <SshHostVerification
              inspection={trust.inspection}
              confirmed={confirmed}
              onConfirmed={setConfirmed}
            />
          ) : null}

          {step === "review" && <div className="dns-change-review-step">
            {error && <InlineError message={error} />}
            <p>{t("vps.repair.reviewTarget", { name: profile.name, host: profile.endpoint.host, port })}</p>
            <DnsChangeReview choice={dnsChoice} endpoints={dnsEndpoints} privateChoice={privateDnsChoice} records={privateDnsRecords} splitDns={splitDns} />
          </div>}

          {step === "repairing" ? (
            <OperationProgress title={dns ? t("vps.repair.progressDns") : t("vps.repair.progress")}
              steps={stepsAt([t("vps.common.step.identity"), t(dns ? "vps.repair.stepDns" : "vps.repair.step"), t("vps.common.step.refresh")], phase)} />
          ) : null}

          {step === "success" && result ? (
            <RepairSummary profile={profile} result={result} dnsPreserved={dnsChoice === "preserve"} recordsPreserved={privateDnsChoice === "preserve"} />
          ) : null}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
