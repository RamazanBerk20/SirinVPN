import { ArrowClockwise, CheckCircle, CloudArrowUp, ShieldCheck, Trash } from "@phosphor-icons/react";
import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../../api";
import { CopyButton } from "../../components/CopyButton";
import { SecretInput } from "../../components/SecretInput";
import { Field, InlineError } from "../../components/ui";
import { t } from "../../i18n";
import { confirmAction } from "../../lib/confirmAction";
import { errorMessage } from "../../lib/errors";
import { registerNavigationGuard } from "../../lib/navigationGuard";
import { isAndroid } from "../../platform";
import type { CreatedHetznerServer, HetznerCatalog, HetznerReady, ProvisionResult } from "../../types";
import { SetupFlow, type SetupNext, type SetupStep } from "./SetupFlow";

type Phase = "plan" | "creating" | "waiting" | "failed" | "install" | "kept" | "deleted";
// Android forgets protected inputs 10 minutes after they are entered (SecretInputs.kt).
const ANDROID_TOKEN_LIFETIME_MS = 590_000;

/** Types offered in a location, cheapest first; the first x86 type is the default. */
export function plansFor(catalog: HetznerCatalog, location: string) {
  const total = (type: HetznerCatalog["server_types"][number]) =>
    Number(type.prices.find(price => price.location === location)?.total_monthly);
  return catalog.server_types
    .filter(type => type.prices.some(price => price.location === location))
    .sort((a, b) => Number(a.architecture !== "x86") - Number(b.architecture !== "x86") || total(a) - total(b));
}

export function HetznerFlow({ onComplete, onDone, onStepChange, compact = false }: {
  onComplete: (result: ProvisionResult, next?: SetupNext) => Promise<void>;
  /** Leaves the flow from its end states (kept or deleted server). */
  onDone?: () => void;
  onStepChange?: (step: SetupStep) => void;
  compact?: boolean;
}) {
  const [token, setToken] = useState("");
  const tokenEntered = useRef(0);
  const [catalog, setCatalog] = useState<HetznerCatalog | null>(null);
  const [location, setLocation] = useState("");
  const [serverType, setServerType] = useState("");
  const [phase, setPhase] = useState<Phase>("plan");
  const [created, setCreated] = useState<CreatedHetznerServer | null>(null);
  const [ready, setReady] = useState<HetznerReady | null>(null);
  const [setupStep, setSetupStep] = useState<SetupStep>("details");
  const [busy, setBusy] = useState<"" | "plans" | "delete">("");
  const [error, setError] = useState("");
  // Which request a "Try again" repeats; resolved at render so it uses the current token.
  const [retry, setRetry] = useState<"" | "delete">("");

  const plans = useMemo(() => catalog ? plansFor(catalog, location) : [], [catalog, location]);
  const plan = plans.find(type => type.name === serverType);
  const price = plan?.prices.find(item => item.location === location);
  const locationName = catalog?.locations.find(item => item.name === location)?.city ?? location;
  const server = created?.server;
  // Until it is installed or deleted, the server bills the Owner: leaving needs a decision.
  // While the create request runs, the server may exist before its name is known.
  const unresolved = (phase === "creating" || server !== undefined) && !["kept", "deleted"].includes(phase) && setupStep !== "success";
  // While the server is being created the flow can't be left, so the parent hides its back link.
  const reportedStep = phase === "creating" || phase === "waiting" ? "installing" : setupStep;
  useEffect(() => onStepChange?.(reportedStep), [reportedStep, onStepChange]);
  useEffect(() => {
    if (!unresolved) return;
    return registerNavigationGuard(() => phase !== "creating" && phase !== "waiting" && setupStep !== "installing"
      && window.confirm(t("onboarding.hetzner.leaveWarning")));
  }, [unresolved, phase, setupStep]);

  const fail = (message: string, again: typeof retry = "") => { setError(message); setRetry(again); };
  const tokenUsable = () => {
    if (!isAndroid || Date.now() - tokenEntered.current < ANDROID_TOKEN_LIFETIME_MS) return true;
    setToken("");
    fail(t("onboarding.hetzner.tokenExpired"));
    return false;
  };

  const loadPlans = async () => {
    if (!tokenUsable()) return;
    setBusy("plans");
    fail("");
    try {
      const loaded = await api.hetznerCatalog(token);
      const first = loaded.locations[0]?.name ?? "";
      setCatalog(loaded);
      setLocation(first);
      setServerType(plansFor(loaded, first)[0]?.name ?? "");
    } catch (reason) {
      // The form's Show prices button is the retry.
      fail(errorMessage(reason, t("onboarding.hetzner.error.catalog")));
    } finally { setBusy(""); }
  };

  const chooseLocation = (next: string) => {
    setLocation(next);
    if (catalog && !plansFor(catalog, next).some(type => type.name === serverType)) setServerType(plansFor(catalog, next)[0]?.name ?? "");
  };

  const wait = async (target: CreatedHetznerServer) => {
    if (!tokenUsable()) { setPhase("failed"); return; }
    setPhase("waiting");
    fail("");
    try {
      setReady(await api.waitHetznerServer(token, target.server));
      setPhase("install");
    } catch (reason) {
      fail(errorMessage(reason, t("onboarding.hetzner.error.wait")));
      setPhase("failed");
    }
  };

  const create = async () => {
    if (!plan || !price || !catalog || !tokenUsable()) return;
    if (!await confirmAction({
      title: t("onboarding.hetzner.confirm.title"),
      message: t("onboarding.hetzner.confirm.message", { type: plan.name, location: locationName, total: price.total_monthly, currency: catalog.currency }),
      confirm: t("onboarding.hetzner.confirm.confirm"),
    })) return;
    setPhase("creating");
    fail("");
    try {
      const result = await api.createHetznerServer(token, { location, server_type: plan.name, accepted_monthly_price: price.total_monthly });
      setCreated(result);
      await wait(result);
    } catch (reason) {
      // No bare Try again: retrying a paid create stays on the button that shows the price.
      fail(errorMessage(reason, t("onboarding.hetzner.error.create")));
      setPhase("plan");
    }
  };

  const remove = async () => {
    if (!server || !tokenUsable() || !await confirmAction({
      title: t("onboarding.hetzner.deleteConfirm.title", { name: server.name }),
      message: t("onboarding.hetzner.deleteConfirm.message", { name: server.name }),
      confirm: t("onboarding.hetzner.deleteConfirm.confirm"),
    })) return;
    setBusy("delete");
    fail("");
    try {
      await api.deleteHetznerServer(token, server);
      setPhase("deleted");
    } catch (reason) {
      fail(errorMessage(reason, t("onboarding.hetzner.error.delete")), "delete");
    } finally { setBusy(""); }
  };

  const startOver = () => { setCreated(null); setReady(null); setSetupStep("details"); fail(""); setPhase("plan"); };
  const again = retry === "delete" ? remove : undefined;
  const errorBox = error && <InlineError message={error} onRetry={again && (() => void again())} retryDisabled={busy !== "" || !token} />;
  const tokenField = <Field label={t("onboarding.hetzner.token")} hint={t("onboarding.hetzner.tokenHint")}>
    <SecretInput type="password" value={token} disabled={busy !== ""} autoComplete="off" spellCheck={false}
      aria-label={t("onboarding.hetzner.token")} onChange={event => { tokenEntered.current = Date.now(); setToken(event.target.value); }} />
  </Field>;
  // Deleting is the one irreversible action here: kept apart, last, and styled as destructive.
  const dangerZone = server && <section className="hetzner-danger-zone" aria-label={t("onboarding.hetzner.dangerLabel")}>
    <p>{t("onboarding.hetzner.billed", { name: server.name })}</p>
    <button type="button" className="secondary-button danger-text" disabled={busy !== "" || !token} onClick={() => void remove()}>
      {busy === "delete" ? <ArrowClockwise className="spin" size={17} /> : <Trash size={17} />}
      {busy === "delete" ? t("onboarding.hetzner.deleting", { name: server.name }) : t("onboarding.hetzner.delete")}
    </button>
  </section>;
  const serverFacts = server && <dl className="hetzner-facts">
    <div><dt>{t("onboarding.hetzner.hostKey")}</dt><dd><code>{server.host_key_sha256}</code><CopyButton value={server.host_key_sha256} label={t("onboarding.setup.fingerprint.copy")} /></dd></div>
    {created?.private_key_path && <div><dt>{t("onboarding.hetzner.keyPath")}</dt><dd><code>{created.private_key_path}</code><CopyButton value={created.private_key_path} label={t("onboarding.setup.created.copyKey")} /></dd></div>}
  </dl>;

  if (phase === "creating" || phase === "waiting") return <div className="install-state" aria-live="polite">
    <div className="install-orbit"><CloudArrowUp size={32} weight="duotone" /></div>
    <h2>{phase === "creating" ? t("onboarding.hetzner.creating") : t("onboarding.hetzner.waiting", { name: server?.name ?? "" })}</h2>
    <p>{t("onboarding.hetzner.waitingHint")}</p>
    <p className="install-keep-open">{t("onboarding.setup.installing.keepOpen")}</p>
    {phase === "waiting" && <button type="button" className="secondary-button" onClick={() => void api.cancelHetznerWait()}>{t("onboarding.hetzner.cancel")}</button>}
  </div>;

  if (phase === "deleted" && server) return <div className="success-state hetzner-end">
    <span className="success-icon"><Trash size={28} weight="duotone" /></span>
    <h2>{t("onboarding.hetzner.deletedTitle", { name: server.name })}</h2>
    <p>{t("onboarding.hetzner.deleted")}</p>
    <div className="install-success-actions">
      {onDone && <button type="button" className="secondary-button" onClick={onDone}>{t("common.action.done")}</button>}
      <button type="button" className="primary-button" onClick={startOver}>{t("onboarding.hetzner.startOver")}</button>
    </div>
  </div>;

  if (phase === "kept" && server) return <div className="success-state hetzner-end">
    <span className="success-icon"><CheckCircle size={28} weight="duotone" /></span>
    <h2>{t("onboarding.hetzner.keptTitle", { name: server.name })}</h2>
    <p>{t("onboarding.hetzner.kept")}</p>
    {serverFacts}
    <div className="install-success-actions">
      {onDone && <button type="button" className="primary-button" onClick={onDone}>{t("common.action.done")}</button>}
    </div>
  </div>;

  if (phase === "failed" && created && server) return <div className="setup-form hetzner-not-ready">
    <h2>{t("onboarding.hetzner.failedTitle", { name: server.name })}</h2>
    {errorBox}
    <p>{t("onboarding.hetzner.failedSummary")}</p>
    {serverFacts}
    {!token && tokenField}
    <div className="fingerprint-actions">
      <button type="button" className="primary-button" disabled={busy !== "" || !token} onClick={() => void wait(created)}>{t("onboarding.hetzner.waitAgain")}</button>
      <button type="button" className="secondary-button" disabled={busy !== ""} onClick={() => { fail(""); setPhase("kept"); }}>{t("onboarding.hetzner.keep")}</button>
    </div>
    {dangerZone}
  </div>;

  if (phase === "install" && created && server && ready) return <div className="hetzner-install">
    <SetupFlow compact={compact} onStepChange={setSetupStep}
      created={{ name: server.name, host: ready.ipv4, host_key_sha256: ready.host_key_sha256, private_key_path: created.private_key_path }}
      onComplete={async (result, next) => { setToken(""); await onComplete(result, next); }}>
      {setupStep === "details" && <>{errorBox}{!token && tokenField}{dangerZone}</>}
    </SetupFlow>
  </div>;

  return <form className={`setup-form ${compact ? "compact" : ""}`} onSubmit={event => { event.preventDefault(); void (catalog ? create() : loadPlans()); }}>
    <div className="form-heading">
      <span><CloudArrowUp size={20} /></span>
      <div><h2>{t("onboarding.hetzner.title")}</h2><p>{t("onboarding.hetzner.summary")}</p></div>
    </div>
    {tokenField}
    {catalog && <>
      <Field label={t("onboarding.hetzner.location")}>
        <select value={location} disabled={busy !== ""} onChange={event => chooseLocation(event.target.value)}>
          {catalog.locations.map(item => <option key={item.name} value={item.name}>{`${item.city}, ${item.country} (${item.name})`}</option>)}
        </select>
      </Field>
      <Field label={t("onboarding.hetzner.serverType")}>
        <select className="hetzner-plan-select" value={serverType} disabled={busy !== ""} onChange={event => setServerType(event.target.value)}>
          {plans.map(type => <option key={type.name} value={type.name}>{t("onboarding.hetzner.typeOption", {
            name: type.name, architecture: type.architecture, cores: type.cores, memory: type.memory_gb, disk: type.disk_gb,
            price: type.prices.find(item => item.location === location)?.total_monthly ?? "", currency: catalog.currency,
          })}</option>)}
        </select>
      </Field>
      {price && <p className="hetzner-price" role="status"><ShieldCheck size={18} aria-hidden="true" /><span>{price.ipv4_monthly
        ? t("onboarding.hetzner.price", { total: price.total_monthly, currency: catalog.currency, server: price.server_monthly, ipv4: price.ipv4_monthly })
        : t("onboarding.hetzner.priceNoIpv4", { total: price.total_monthly, currency: catalog.currency })}</span></p>}
    </>}
    {errorBox}
    <button className="primary-button" type="submit" disabled={busy !== "" || !token || (catalog !== null && !price)}>
      {busy === "plans" ? <><ArrowClockwise className="spin" size={17} />{t("onboarding.hetzner.loading")}</> : catalog && price
        ? t("onboarding.hetzner.create", { total: price.total_monthly, currency: catalog.currency })
        : t("onboarding.hetzner.loadPlans")}
    </button>
  </form>;
}
