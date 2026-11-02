import { confirmAction } from "../../lib/confirmAction";
import { TransportSetupFields, newTransportDraft, transportDraftIsValid, transportSetupFromDraft } from "../settings/TransportSetupFields";
import { useSshLogin } from "../../hooks/useSshLogin";
import { SplitDnsFields, splitDnsDraftIsValid, withSplitDns } from "../dns/SplitDnsFields";
import { SshLoginFields } from "../settings/SshLoginFields";
import { SshVerificationGuide } from "../settings/SshVerificationGuide";
import { CaretRight, CheckCircle, CloudCheck, Key, TerminalWindow, Warning } from "@phosphor-icons/react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "../../api";
import { privateDnsDraftIsValid, privateDnsRecordsFromDraft } from "../../dns";
import { validateHost } from "../../format";
import { type NetworkPreflight, type ProvisionResult } from "../../types";
import { ServerNetworkPreflight } from "../settings/ServerNetworkPreflight";
import { Field, InlineError } from "../../components/ui";
import { CopyButton } from "../../components/CopyButton";
import { errorMessage } from "../../lib/errors";
import { registerNavigationGuard } from "../../lib/navigationGuard";
import { t } from "../../i18n";
import {
  type DnsPolicyChoice,
  type DnsEndpointDraft,
  newDnsEndpointDrafts,
  dnsDraftIsValid,
  dnsUpstreamFromDraft,
  PrivateDnsRecordFields,
  DnsPolicyFields,
  Nat64Fields,
  nat64PrefixIsValid,
} from "../dns/DnsFields";
import { FingerprintValue, InstallFailure, InstallProgress, InstallSuccess, SetupProgress, StepBack } from "./SetupOutcome";

export type SetupStep = "details" | "fingerprint" | "installing" | "failed" | "success";
/** Where the app goes after a finished setup; "recovery" opens Keys & recovery for the new server. */
export type SetupNext = "recovery";

/** A server SirinVPN just created: its address and SSH host key are already known. */
export interface CreatedServer {
  /** The provider's name for the server, e.g. sirinvpn-fsn1. */
  name: string;
  host: string;
  host_key_sha256: string;
  /** Desktop keeps the generated login key in a file; Android saves it as the login. */
  private_key_path: string | null;
}

export function SetupFlow({
  onComplete,
  compact = false,
  created,
  onStepChange,
  children,
}: {
  onComplete: (result: ProvisionResult, next?: SetupNext) => Promise<void>;
  compact?: boolean;
  created?: CreatedServer;
  onStepChange?: (step: SetupStep) => void;
  /** Provider actions shown under a created server's ready step. */
  children?: ReactNode;
}) {
  const [step, setStep] = useState<SetupStep>("details");
  const [name, setName] = useState(() => t("onboarding.setup.defaultName"));
  const [host, setHost] = useState(created?.host ?? "");
  const login = useSshLogin(host);
  const [busy, setBusy] = useState(false);
  const [replaceExistingInstallation, setReplaceExistingInstallation] =
    useState(false);
  const [dnsChoice, setDnsChoice] = useState<DnsPolicyChoice>("recursive");
  const [dnsEndpoints, setDnsEndpoints] =
    useState<DnsEndpointDraft[]>(newDnsEndpointDrafts);
  const [privateDnsRecords, setPrivateDnsRecords] = useState("");
  const [splitDns, setSplitDns] = useState("");
  const [transport, setTransport] = useState(() => newTransportDraft());
  const [fingerprint, setFingerprint] = useState(created?.host_key_sha256 ?? "");
  // The verified fingerprint and network check stay valid until the address, SSH port or ports change.
  const [verifiedFor, setVerifiedFor] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [checkedFor, setCheckedFor] = useState("");
  const [result, setResult] = useState<ProvisionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [installError, setInstallError] = useState("");
  const [preflight, setPreflight] = useState<NetworkPreflight | null>(null);
  const [nat64Prefix, setNat64Prefix] = useState("");
  const [focusPort, setFocusPort] = useState(false);
  const form = useRef<HTMLFormElement>(null);
  const ipv6Only = preflight?.issues.some((issue) => issue.code === "ipv6_only") ?? false;
  const nat64 = ipv6Only ? nat64Prefix.trim() : "";
  const target = `${host.trim()}:${login.port}`;
  const networkFor = JSON.stringify([target, transportSetupFromDraft(transport)]);
  // The backend saves the profile once provisioning succeeds. Until "Open
  // server" hands it to the app, report it on unmount so it is never lost.
  const unopened = useRef<ProvisionResult | null>(null);
  const mounted = useRef(false);
  const complete = useRef(onComplete);
  complete.current = onComplete;
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      const pending = unopened.current;
      unopened.current = null;
      if (pending) void complete.current(pending);
    };
  }, []);
  useEffect(() => step === "installing" ? registerNavigationGuard(() => false) : undefined, [step]);
  useEffect(() => onStepChange?.(step), [step, onStepChange]);
  // Fill in the generated key once the saved-login lookup is done, replacing any stale login.
  const prefilled = useRef(false);
  useEffect(() => {
    if (!created?.private_key_path || login.loading || prefilled.current) return;
    prefilled.current = true;
    login.edit();
    login.setUsername("root");
    login.setPort("22");
    login.setAuth("private_key");
    login.setKeyPath(created.private_key_path);
  }, [created, login]);
  // "Change port" returns here with the conflicting port field opened and focused.
  useEffect(() => {
    if (step !== "details" || !focusPort || !form.current) return;
    setFocusPort(false);
    const conflicts = preflight?.issues.filter((issue) => issue.blocking).map((issue) => issue.message).join(" ") ?? "";
    const ports = [...form.current.querySelectorAll<HTMLInputElement>(".advanced-fields input[inputmode=numeric]")];
    const field = ports.find((port) => new RegExp(`\\b${port.value}\\b`).test(conflicts)) ?? ports[0];
    if (!field) return;
    for (let disclosure = field.closest("details"); disclosure; disclosure = disclosure.parentElement?.closest("details") ?? null) disclosure.open = true;
    field.focus();
    field.select();
  }, [step, focusPort, preflight]);

  const valid =
    validateHost(host) &&
    name.trim().length > 0 &&
    login.valid &&
    transportDraftIsValid(transport) &&
    dnsDraftIsValid(dnsChoice, dnsEndpoints) &&
    splitDnsDraftIsValid(splitDns) &&
    privateDnsDraftIsValid(privateDnsRecords, true);
  const blocked = preflight?.issues.some((issue) => issue.blocking) ?? false;
  const portConflict = preflight?.issues.some((issue) => issue.code === "port_conflict") ?? false;
  const installable = preflight !== null && !blocked && (nat64 === "" || nat64PrefixIsValid(nat64));

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
    if (!valid || busy) return;
    setError(null);
    if (checkedFor !== networkFor) setPreflight(null);
    if (verifiedFor === target) {
      setStep("fingerprint");
      return;
    }
    setBusy(true);
    try {
      setFingerprint(await api.probeHostKey(host.trim(), Number(login.port)));
      setVerifiedFor(target);
      setConfirmed(false);
      setPreflight(null);
      setStep("fingerprint");
    } catch {
      setError(t("onboarding.setup.error.unreachable"));
    } finally {
      setBusy(false);
    }
  };

  const inspectNetwork = async (pin = fingerprint): Promise<NetworkPreflight | null> => {
    if (busy) return null;
    setBusy(true);
    setError(null);
    setConfirmed(true);
    setPreflight(null);
    try {
      const report = await api.inspectServerNetwork({
        ssh: { host: host.trim(), ...(await login.prepare(pin)) },
        transport: transportSetupFromDraft(transport),
      });
      setPreflight(report);
      setCheckedFor(networkFor);
      return report;
    } catch (reason) {
      setError(errorMessage(reason, t("onboarding.setup.error.network")));
      return null;
    } finally { setBusy(false); }
  };

  const provision = async (pin = fingerprint) => {
    if (
      replaceExistingInstallation &&
      !await confirmAction({
        title: t("onboarding.setup.confirmReplace.title"),
        message: t("onboarding.setup.confirmReplace.message"),
        confirm: t("onboarding.setup.confirmReplace.confirm"),
      })
    )
      return;
    setStep("installing");
    setError(null);
    setInstallError("");
    try {
      const provisioned = await api.provisionServer({
        name: name.trim(),
        host: host.trim(),
        ...(await login.prepare(pin)),
        replace_existing_installation: replaceExistingInstallation,
        transport: transportSetupFromDraft(transport),
        dns_upstream: withSplitDns(
          dnsChoice === "dns_over_tls" || dnsChoice === "dns_over_https"
            ? dnsUpstreamFromDraft(dnsChoice, dnsEndpoints)
            : { mode: "recursive" }, splitDns),
        private_dns_records: privateDnsRecordsFromDraft(privateDnsRecords),
        nat64_prefix: nat64 || null,
      });
      login.clearSecrets();
      if (!mounted.current) {
        void complete.current(provisioned);
        return;
      }
      unopened.current = provisioned;
      setResult(provisioned);
      setStep("success");
    } catch (reason) {
      login.clearSecrets();
      setInstallError(errorMessage(reason, t("onboarding.setup.error.install")));
      setStep("failed");
    }
  };

  // A created server needs no fingerprint check: Install checks the network and goes straight on unless it needs a decision.
  const installCreated = async () => {
    if (!created || !valid || busy) return;
    setFingerprint(created.host_key_sha256);
    const report = await inspectNetwork(created.host_key_sha256);
    if (!report) return;
    if (report.issues.some((issue) => issue.blocking || issue.code === "ipv6_only")) setStep("fingerprint");
    else await provision(created.host_key_sha256);
  };

  const finish = (next?: SetupNext) => {
    if (!result) return;
    unopened.current = null;
    void (next ? onComplete(result, next) : onComplete(result));
  };

  if (step === "installing") return <InstallProgress host={host.trim()} steps={!created} />;

  if (step === "failed") return <InstallFailure error={installError} fingerprint={fingerprint} steps={!created}
    canRetry={login.valid} onRetry={() => void provision()} onBack={() => setStep("details")} />;

  if (step === "success" && result) return <InstallSuccess result={result} onOpen={() => finish()} onRecoveryKey={() => finish("recovery")} />;

  if (step === "fingerprint") {
    return (
      <div className="fingerprint-step">
        <StepBack onClick={() => setStep("details")} disabled={busy} />
        {!created && <SetupProgress current={1} />}
        <div className="fingerprint-heading">
          <Key size={28} weight="duotone" aria-hidden="true" />
          <h2>{t(created ? "onboarding.setup.fingerprint.pinnedTitle" : "onboarding.setup.fingerprint.title")}</h2>
        </div>
        <p>{t(created ? "onboarding.setup.fingerprint.pinned" : "onboarding.setup.fingerprint.summary")}</p>
        <FingerprintValue value={fingerprint} />
        {!created && !confirmed && <SshVerificationGuide confirmation="button" />}
        {!created && !confirmed && <div className="warning-note">
          <Warning size={18} weight="fill" />
          <span>{t("onboarding.setup.fingerprint.mismatch")}</span>
        </div>}
        {!created && confirmed && <div className="fingerprint-confirmed"><CheckCircle size={18} weight="fill" />{t("onboarding.setup.fingerprint.confirmed")}</div>}
        {replaceExistingInstallation && <div className="danger-callout" role="note">
          <Warning size={20} weight="fill" />
          <span>{t("onboarding.setup.fingerprint.replaceWarning")}</span>
        </div>}
        {preflight && <ServerNetworkPreflight report={preflight} />}
        {portConflict && <button type="button" className="secondary-button change-port" disabled={busy} onClick={() => { setFocusPort(true); setStep("details"); }}>
          {t("onboarding.setup.fingerprint.changePort")}
        </button>}
        {ipv6Only && <Nat64Fields choice="replace" value={nat64Prefix} allowPreserve={false} onChoiceChange={() => undefined} onValueChange={setNat64Prefix} />}
        {error && <InlineError message={error} />}
        <div className="fingerprint-actions">
          <button className={preflight ? "secondary-button" : "primary-button"} disabled={busy} onClick={() => void inspectNetwork()}>
            {busy ? t("onboarding.setup.fingerprint.checking")
              : confirmed ? t("onboarding.setup.fingerprint.checkAgain")
              : created ? t("onboarding.setup.fingerprint.checkNetwork") : t("onboarding.setup.fingerprint.matches")}
          </button>
          {preflight && <button className={`primary-button${replaceExistingInstallation ? " danger-action" : ""}`} disabled={busy || !installable} onClick={() => void provision()}>
            {replaceExistingInstallation ? t("onboarding.setup.fingerprint.replace") : t("onboarding.setup.fingerprint.install")}
          </button>}
        </div>
      </div>
    );
  }

  const advanced = <div className="setup-advanced-content">
    <TransportSetupFields value={transport} onChange={setTransport} />
    <DnsPolicyFields
      choice={dnsChoice}
      endpoints={dnsEndpoints}
      allowPreserve={false}
      onChoiceChange={setDnsChoice}
      onEndpointChange={updateDnsEndpoint}
    />
    <PrivateDnsRecordFields
      choice="replace"
      value={privateDnsRecords}
      allowPreserve={false}
      onChoiceChange={() => undefined}
      onValueChange={setPrivateDnsRecords}
    />
    <SplitDnsFields value={splitDns} onChange={setSplitDns} />
    <label className={`replacement-option danger-option ${replaceExistingInstallation ? "selected" : ""}`}>
      <input
        type="checkbox"
        checked={replaceExistingInstallation}
        onChange={(event) => setReplaceExistingInstallation(event.target.checked)}
      />
      <span>
        <strong>{t("onboarding.setup.replace.title")}</strong>
        <small>{t("onboarding.setup.replace.summary")}</small>
      </span>
    </label>
  </div>;
  const nameField = <Field label={t("onboarding.setup.name")} hint={t("onboarding.setup.nameHint")}>
    <input value={name} onChange={(event) => setName(event.target.value)} autoComplete="off" />
  </Field>;

  if (created) {
    return (
      <form ref={form} className={`setup-form created-server ${compact ? "compact" : ""}`} onSubmit={(event) => { event.preventDefault(); void installCreated(); }}>
        <div className="ready-heading">
          <span><CloudCheck size={26} weight="duotone" /></span>
          <div>
            <h2>{t("onboarding.setup.created.title", { name: created.name })}</h2>
            <p>{t("onboarding.setup.created.summary", { host: created.host })}</p>
          </div>
        </div>
        <fieldset className="setup-fields" disabled={busy}>
          {/* Opens itself only when the prefilled sign-in turned out unusable. */}
          <details className="setup-advanced" open={!login.loading && !login.valid && (prefilled.current || !created.private_key_path)}>
            <summary>{t("onboarding.setup.created.settings")}</summary>
            <div className="setup-advanced-content">
              {nameField}
              <div className="created-facts">
                <span>{t("onboarding.setup.created.address")}</span><code>{created.host}</code>
                {created.private_key_path && <><span>{t("onboarding.setup.created.key")}</span>
                  <span className="created-key"><code>{created.private_key_path}</code><CopyButton value={created.private_key_path} label={t("onboarding.setup.created.copyKey")} /></span></>}
              </div>
              {!login.valid && <SshLoginFields login={login} />}
              {advanced}
            </div>
          </details>
        </fieldset>
        {error && <InlineError message={error} />}
        <button className="primary-button" type="submit" disabled={!valid || busy}>
          {busy ? t("onboarding.setup.fingerprint.checking") : t("onboarding.setup.fingerprint.install")}
        </button>
        {children}
      </form>
    );
  }

  return (
    <form
      ref={form}
      className={`setup-form ${compact ? "compact" : ""}`}
      onSubmit={(event) => {
        event.preventDefault();
        void inspect();
      }}
    >
      <SetupProgress current={0} />
      <div className="form-heading">
        <span>
          <TerminalWindow size={20} />
        </span>
        <div>
          <h2>{t("onboarding.setup.title")}</h2>
          <p>{t("onboarding.setup.summary")}</p>
        </div>
      </div>
      <fieldset className="setup-fields" disabled={busy}>
        {nameField}
        <Field label={t("onboarding.setup.host")}>
          <input
            value={host}
            onChange={(event) => setHost(event.target.value)}
            placeholder={t("onboarding.setup.hostPlaceholder")}
            autoCapitalize="none"
            spellCheck={false}
          />
        </Field>
        <SshLoginFields login={login} />
        <details className="setup-advanced">
          <summary>{t("onboarding.setup.advanced")}</summary>
          {advanced}
        </details>
      </fieldset>
      {error ? <InlineError message={error} /> : null}
      <button
        className="primary-button"
        type="submit"
        disabled={!valid || busy}
      >
        {busy ? t("onboarding.setup.verifying", { host: host.trim() }) : verifiedFor === target ? t("onboarding.setup.continue") : t("onboarding.setup.verify")}{" "}
        <CaretRight size={17} weight="bold" />
      </button>
    </form>
  );
}
