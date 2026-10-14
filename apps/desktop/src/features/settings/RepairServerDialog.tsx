import { TransportSetupFields, newTransportDraft, transportDraftIsValid, transportSetupFromDraft } from "./TransportSetupFields";
import { DnsChangeReview } from "../dns/DnsChangeReview";
import { useSshLogin } from "../../hooks/useSshLogin";
import { SshLoginFields } from "./SshLoginFields";
import { RepairSummary } from "./RepairSummary";
import { DialogContent } from "../../components/DialogContent";
import * as Dialog from "@radix-ui/react-dialog";
import {
  ArrowClockwise,
  GlobeHemisphereWest,
} from "@phosphor-icons/react";
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
  type DnsEndpointDraft,
  newDnsEndpointDrafts,
  dnsDraftIsValid,
  dnsUpstreamFromDraft,
  PrivateDnsRecordFields,
  DnsPolicyFields,
} from "../dns/DnsFields";

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
  intent?: "repair" | "dns";
}) {
  const formId = useId();
  const [step, setStep] = useState<
    "details" | "fingerprint" | "review" | "repairing" | "success"
  >("details");
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
      setTransport(newTransportDraft(profile));
      setResult(null);
      setError(null);
      setBusy(false);
    }
  }, [open]);

  const changeOpen = (next: boolean) => {
    if (!next && (busy || step === "repairing")) return;
    onOpenChange(next);
  };

  const sshValid =
    disconnected &&
    login.valid &&
    (intent === "dns" || transportDraftIsValid(transport)) &&
    dnsDraftIsValid(dnsChoice, dnsEndpoints) &&
    (dnsChoice === "preserve" || splitDnsDraftIsValid(splitDns)) &&
    (privateDnsChoice !== "replace" ||
      privateDnsDraftIsValid(privateDnsRecords, false));

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
        if (intent === "dns") setStep("review");
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
    setBusy(true);
    setError(null);
    try {
      const fingerprint = await trust.accept(checked, confirmed);
      const repaired = await api.repairServer({
        server_id: profile.id,
        ...(await login.prepare(fingerprint)),
        confirmed: true,
        transport: intent === "dns" ? null : transportSetupFromDraft(transport, profile),
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
      });
      clearSecrets();
      await onCompleted();
      setResult(repaired);
      setStep("success");
    } catch (reason) {
      clearSecrets();
      setConfirmed(false);
      setStep("details");
      setError(
        errorMessage(reason, intent === "dns" ? t("vps.repair.error.dns") : t("vps.repair.error.repair")),
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content remove-server-dialog repair-server-dialog"
          heading={step === "repairing"
              ? intent === "dns" ? t("vps.repair.titleRunningDns") : t("vps.repair.titleRunning")
              : step === "success" ? intent === "dns" ? t("vps.repair.titleDoneDns") : t("vps.repair.titleDone")
              : intent === "dns" ? t("vps.repair.titleDns", { name: profile.name }) : t("vps.repair.title", { name: profile.name })}
          description={step === "success"
            ? t("vps.repair.description.done")
            : step === "repairing"
              ? t("vps.repair.description.running")
              : intent === "dns" ? t("vps.repair.description.dns") : t("vps.repair.description.repair")}
          closeDisabled={busy || step === "repairing"}
          footer={step === "repairing" ? <p role="status">{t("vps.common.keepOpen")}</p>
            : step === "success" ? <button className="primary-button" type="button" onClick={() => { onOpenChange(false); onReturnHome?.(); }}>{t("vps.repair.action.home")}</button>
            : <>
              <button className="secondary-button" type="button" disabled={busy} onClick={() => changeOpen(false)}>{t("common.action.cancel")}</button>
              {step === "details" ? <button className="primary-button" type="submit" form={formId} disabled={!sshValid || busy}>{busy ? t("vps.common.checking") : intent === "dns" ? t("vps.repair.action.review") : t("vps.repair.action.repair")}</button>
                : <button className="primary-button" type="button" disabled={busy || !sshValid || step === "fingerprint" && !confirmed} onClick={() => { if (intent === "dns" && step === "fingerprint") setStep("review"); else void repair(); }}>{intent === "dns" ? step === "fingerprint" ? t("vps.repair.action.review") : t("vps.repair.action.apply") : t("vps.repair.action.repair")}</button>}
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
              <fieldset disabled={busy} className="ssh-operation-fields">
                <div className="uninstall-target">
                  <GlobeHemisphereWest size={16} />
                  <code>{profile.endpoint.host}</code>
                </div>
                {!disconnected ? (
                  <InlineError message={t("vps.common.disconnectFirst")} />
                ) : null}
                <SshLoginFields login={login} />
                {intent !== "dns" && <TransportSetupFields value={transport} onChange={setTransport} existing />}
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
                {intent !== "dns" && <p className="settings-note">{t("vps.repair.note")}</p>}
                {error ? <InlineError message={error} /> : null}
              </fieldset>
            </form>
          ) : null}

          {step === "fingerprint" && trust.inspection ? (
            <div className="uninstall-fingerprint repair-fingerprint">
              <button
                className="back-button"
                onClick={() => setStep("details")}
              >
                {t("common.action.back")}
              </button>
              <SshHostVerification
                inspection={trust.inspection}
                confirmed={confirmed}
                onConfirmed={setConfirmed}
              />
              {!disconnected && <InlineError message={t("vps.common.disconnectFirst")} />}
            </div>
          ) : null}

          {step === "review" && <>
            <button type="button" className="back-button" disabled={busy} onClick={() => setStep("details")}>{t("common.action.back")}</button>
            <p>{t("vps.repair.reviewTarget", { name: profile.name, host: profile.endpoint.host, port })}</p>
            <DnsChangeReview choice={dnsChoice} endpoints={dnsEndpoints} privateChoice={privateDnsChoice} records={privateDnsRecords} splitDns={splitDns} />
            {!disconnected && <InlineError message={t("vps.common.disconnectFirst")} />}
            {error && <InlineError message={error} />}
          </>}

          {step === "repairing" ? (
            <div className="uninstall-progress repair-progress">
              <ArrowClockwise className="spin" size={26} />
              <strong>{t("vps.repair.progress")}</strong>
            </div>
          ) : null}

          {step === "success" && result ? (
            <RepairSummary profile={profile} result={result} dnsPreserved={dnsChoice === "preserve"} recordsPreserved={privateDnsChoice === "preserve"} />
          ) : null}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
