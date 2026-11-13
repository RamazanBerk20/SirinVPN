import { ArrowClockwise, CheckCircle, CloudArrowUp, MagnifyingGlass, ShieldCheck, Trash, Warning } from "@phosphor-icons/react";
import { useEffect, useMemo, useReducer, useRef, useState } from "react";
import { api } from "../../api";
import { CopyButton } from "../../components/CopyButton";
import { SecretInput } from "../../components/SecretInput";
import { Field, InlineError } from "../../components/ui";
import { formatNumber, intlLocale, t } from "../../i18n";
import { confirmAction } from "../../lib/confirmAction";
import { appError, errorMessage } from "../../lib/errors";
import { registerNavigationGuard } from "../../lib/navigationGuard";
import { isAndroid } from "../../platform";
import type { CreatedHetznerServer, HetznerCatalog, ProvisionResult } from "../../types";
import { hetznerReducer, hetznerUnresolved, initialHetzner } from "./hetznerMachine";
import { SetupFlow, type SetupNext, type SetupStep } from "./SetupFlow";

// Android forgets protected inputs 10 minutes after they are entered (SecretInputs.kt).
const ANDROID_TOKEN_LIFETIME_MS = 590_000;

/** A Hetzner price (a decimal string) in the interface language's currency format. */
function money(amount: string, currency: string) {
  try { return formatNumber(Number(amount), { style: "currency", currency }); } catch { return `${amount} ${currency}`; /* not an ISO currency code */ }
}

/** A country code as a name in the interface language; the code itself if the browser has no name for it. */
function countryName(code: string) {
  try { return new Intl.DisplayNames([intlLocale()], { type: "region" }).of(code) ?? code; } catch { return code; }
}

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
  const [state, dispatch] = useReducer(hetznerReducer, initialHetzner);
  const [setupStep, setSetupStep] = useState<SetupStep>("details");
  const deleting = (state.kind === "failed" || state.kind === "install") && state.deleting;
  const busy = state.kind === "loadingPlans" || deleting || state.kind === "uncertain" && state.checking;
  const [error, setError] = useState("");
  // Which request a "Try again" repeats; resolved at render so it uses the current token.
  const [retry, setRetry] = useState<"" | "delete">("");

  const plans = useMemo(() => catalog ? plansFor(catalog, location) : [], [catalog, location]);
  const plan = plans.find(type => type.name === serverType);
  const price = plan?.prices.find(item => item.location === location);
  const locationName = catalog?.locations.find(item => item.name === location)?.city ?? location;
  const created = "created" in state ? state.created : null;
  const server = created?.server;
  // Until it is installed or deleted, the server bills the Owner (or may): leaving needs a decision.
  const unresolved = hetznerUnresolved(state) && setupStep !== "success";
  const blocking = state.kind === "creating" || state.kind === "waiting" || state.kind === "install" && setupStep === "installing";
  const uncertainName = state.kind === "uncertain" ? state.name : null;
  // While the server is being created the flow can't be left, so the parent hides its back link.
  const reportedStep = state.kind === "creating" || state.kind === "waiting" ? "installing" : state.kind === "install" ? setupStep : "details";
  useEffect(() => onStepChange?.(reportedStep), [reportedStep, onStepChange]);
  useEffect(() => {
    if (!unresolved) return;
    return registerNavigationGuard(() => !blocking && window.confirm(uncertainName
      ? t("onboarding.hetzner.uncertain.leaveWarning", { name: uncertainName }) : t("onboarding.hetzner.leaveWarning")));
  }, [unresolved, blocking, uncertainName]);

  const fail = (message: string, again: typeof retry = "") => { setError(message); setRetry(again); };
  const tokenUsable = () => {
    if (!isAndroid || Date.now() - tokenEntered.current < ANDROID_TOKEN_LIFETIME_MS) return true;
    setToken("");
    fail(t("onboarding.hetzner.tokenExpired"));
    return false;
  };

  const loadPlans = async () => {
    if (!tokenUsable()) return;
    dispatch({ type: "loadPlans" });
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
    } finally { dispatch({ type: "plansDone" }); }
  };

  const chooseLocation = (next: string) => {
    setLocation(next);
    if (catalog && !plansFor(catalog, next).some(type => type.name === serverType)) setServerType(plansFor(catalog, next)[0]?.name ?? "");
  };

  const wait = async (target: CreatedHetznerServer) => {
    dispatch({ type: "wait", created: target });
    if (!tokenUsable()) { dispatch({ type: "waitFailed" }); return; }
    fail("");
    try {
      dispatch({ type: "ready", ready: await api.waitHetznerServer(token, target.server) });
    } catch (reason) {
      fail(errorMessage(reason, t("onboarding.hetzner.error.wait")));
      dispatch({ type: "waitFailed" });
    }
  };

  const create = async () => {
    if (!plan || !price || !catalog || !tokenUsable()) return;
    if (!await confirmAction({
      title: t("onboarding.hetzner.confirm.title"),
      message: t("onboarding.hetzner.confirm.message", { type: plan.name, location: locationName, total: money(price.total_monthly, catalog.currency) }),
      confirm: t("onboarding.hetzner.confirm.confirm"),
    })) return;
    dispatch({ type: "create" });
    fail("");
    let result: CreatedHetznerServer;
    try {
      result = await api.createHetznerServer(token, { location, server_type: plan.name, accepted_monthly_price: price.total_monthly });
    } catch (reason) {
      const failure = appError(reason, ["hetzner_create_uncertain"]);
      // The server may exist and bill the Owner: Create stays off until they settle it.
      if (failure.code === "hetzner_create_uncertain") { dispatch({ type: "createUncertain", name: failure.params.server as string }); return; }
      // No bare Try again: retrying a paid create stays on the button that shows the price.
      fail(errorMessage(reason, t("onboarding.hetzner.error.create")));
      dispatch({ type: "createFailed" });
      return;
    }
    await wait(result);
  };

  const check = async () => {
    if (state.kind !== "uncertain" || !tokenUsable()) return;
    dispatch({ type: "check" });
    fail("");
    try {
      dispatch({ type: "checked", found: await api.findHetznerServer(token, state.name) });
    } catch (reason) {
      fail(errorMessage(reason, t("onboarding.hetzner.uncertain.checkFailed")));
      dispatch({ type: "checkFailed" });
    }
  };

  const confirmAbsent = async () => {
    if (state.kind !== "uncertain" || !await confirmAction({
      title: t("onboarding.hetzner.uncertain.absentConfirm.title", { name: state.name }),
      message: t("onboarding.hetzner.uncertain.absentConfirm.message", { name: state.name }),
      confirm: t("onboarding.hetzner.uncertain.absentConfirm.confirm"),
    })) return;
    fail("");
    dispatch({ type: "absent" });
  };

  const remove = async () => {
    if (!server || !tokenUsable() || !await confirmAction({
      title: t("onboarding.hetzner.deleteConfirm.title", { name: server.name }),
      message: t("onboarding.hetzner.deleteConfirm.message", { name: server.name }),
      confirm: t("onboarding.hetzner.deleteConfirm.confirm"),
    })) return;
    dispatch({ type: "delete" });
    fail("");
    try {
      await api.deleteHetznerServer(token, server);
      dispatch({ type: "deleted" });
    } catch (reason) {
      fail(errorMessage(reason, t("onboarding.hetzner.error.delete")), "delete");
      dispatch({ type: "deleteFailed" });
    }
  };

  const startOver = () => { setSetupStep("details"); fail(""); dispatch({ type: "startOver" }); };
  const again = retry === "delete" ? remove : undefined;
  const errorBox = error && <InlineError message={error} onRetry={again && (() => void again())} retryDisabled={busy || !token} />;
  const tokenField = <Field label={t("onboarding.hetzner.token")} hint={t("onboarding.hetzner.tokenHint")}>
    <SecretInput field="apiToken" type="password" value={token} disabled={busy} autoComplete="off" spellCheck={false}
      aria-label={t("onboarding.hetzner.token")} onChange={event => { tokenEntered.current = Date.now(); setToken(event.target.value); }} />
  </Field>;
  // Deleting is the one irreversible action here: kept apart, last, and styled as destructive.
  const dangerZone = server && <section className="hetzner-danger-zone" aria-label={t("onboarding.hetzner.dangerLabel")}>
    <p>{t("onboarding.hetzner.billed", { name: server.name })}</p>
    <button type="button" className="secondary-button danger-text" disabled={busy || !token} onClick={() => void remove()}>
      {deleting ? <ArrowClockwise className="spin" size={17} /> : <Trash size={17} />}
      {deleting ? t("onboarding.hetzner.deleting", { name: server.name }) : t("onboarding.hetzner.delete")}
    </button>
  </section>;
  const serverFacts = server && <dl className="hetzner-facts">
    <div><dt>{t("onboarding.hetzner.hostKey")}</dt><dd><code>{server.host_key_sha256}</code><CopyButton value={server.host_key_sha256} label={t("onboarding.setup.fingerprint.copy")} /></dd></div>
    {created?.private_key_path && <div><dt>{t("onboarding.hetzner.keyPath")}</dt><dd><code>{created.private_key_path}</code><CopyButton value={created.private_key_path} label={t("onboarding.setup.created.copyKey")} /></dd></div>}
  </dl>;

  if (state.kind === "creating" || state.kind === "waiting") return <div className="install-state" aria-live="polite" data-state={state.kind}>
    <div className="install-orbit"><CloudArrowUp size={32} weight="duotone" /></div>
    <h2>{state.kind === "creating" ? t("onboarding.hetzner.creating") : t("onboarding.hetzner.waiting", { name: state.created.server.name })}</h2>
    <p>{t("onboarding.hetzner.waitingHint")}</p>
    <p className="install-keep-open">{t("onboarding.setup.installing.keepOpen")}</p>
    {state.kind === "waiting" && <button type="button" className="secondary-button" onClick={() => void api.cancelHetznerWait()}>{t("onboarding.hetzner.cancel")}</button>}
  </div>;

  if (state.kind === "uncertain") return <div className="setup-form hetzner-uncertain" data-state={state.kind}>
    <div className="warning-note"><Warning size={18} weight="fill" /><span>{t("onboarding.hetzner.uncertain.title", { name: state.name })}</span></div>
    <p>{t("onboarding.hetzner.uncertain.summary", { name: state.name })}</p>
    <dl className="hetzner-facts">
      <div><dt>{t("onboarding.hetzner.uncertain.nameLabel")}</dt><dd><code>{state.name}</code><CopyButton value={state.name} label={t("onboarding.hetzner.uncertain.copyName")} /></dd></div>
    </dl>
    {errorBox}
    {state.found ? <p role="status">{t("onboarding.hetzner.uncertain.found", { name: state.name })}</p>
      : state.checked && <p role="status">{t("onboarding.hetzner.uncertain.notFound", { name: state.name })}</p>}
    {!token && tokenField}
    <div className="fingerprint-actions">
      {state.found
        ? <button type="button" className="primary-button" disabled={busy || !token} onClick={() => void wait(state.found!)}>{t("onboarding.hetzner.uncertain.adopt")}</button>
        : <button type="button" className="primary-button" disabled={busy || !token} onClick={() => void check()}>
          {state.checking ? <ArrowClockwise className="spin" size={17} /> : <MagnifyingGlass size={17} />}
          {state.checking ? t("onboarding.hetzner.uncertain.checking") : t("onboarding.hetzner.uncertain.check")}
        </button>}
      {!state.found && <button type="button" className="secondary-button" disabled={busy} onClick={() => void confirmAbsent()}>{t("onboarding.hetzner.uncertain.absent")}</button>}
    </div>
  </div>;

  if (state.kind === "deleted" && server) return <div className="success-state hetzner-end" data-state={state.kind}>
    <span className="success-icon"><Trash size={28} weight="duotone" /></span>
    <h2>{t("onboarding.hetzner.deletedTitle", { name: server.name })}</h2>
    <p>{t("onboarding.hetzner.deleted")}</p>
    <div className="install-success-actions">
      {onDone && <button type="button" className="secondary-button" onClick={onDone}>{t("common.action.done")}</button>}
      <button type="button" className="primary-button" onClick={startOver}>{t("onboarding.hetzner.startOver")}</button>
    </div>
  </div>;

  if (state.kind === "kept" && server) return <div className="success-state hetzner-end" data-state={state.kind}>
    <span className="success-icon"><CheckCircle size={28} weight="duotone" /></span>
    <h2>{t("onboarding.hetzner.keptTitle", { name: server.name })}</h2>
    <p>{t("onboarding.hetzner.kept")}</p>
    {serverFacts}
    <div className="install-success-actions">
      {onDone && <button type="button" className="primary-button" onClick={onDone}>{t("common.action.done")}</button>}
    </div>
  </div>;

  if (state.kind === "failed" && created && server) return <div className="setup-form hetzner-not-ready" data-state={state.kind}>
    <h2>{t("onboarding.hetzner.failedTitle", { name: server.name })}</h2>
    {errorBox}
    <p>{t("onboarding.hetzner.failedSummary")}</p>
    {serverFacts}
    {!token && tokenField}
    <div className="fingerprint-actions">
      <button type="button" className="primary-button" disabled={busy || !token} onClick={() => void wait(created)}>{t("onboarding.hetzner.waitAgain")}</button>
      <button type="button" className="secondary-button" disabled={busy} onClick={() => { fail(""); dispatch({ type: "keep" }); }}>{t("onboarding.hetzner.keep")}</button>
    </div>
    {dangerZone}
  </div>;

  if (state.kind === "install" && created && server) return <div className="hetzner-install" data-state={state.kind}>
    <SetupFlow compact={compact} onStepChange={setSetupStep}
      created={{ name: server.name, host: state.ready.ipv4, host_key_sha256: state.ready.host_key_sha256, private_key_path: created.private_key_path }}
      onComplete={async (result, next) => { setToken(""); await onComplete(result, next); }}>
      {setupStep === "details" && <>{errorBox}{!token && tokenField}{dangerZone}</>}
    </SetupFlow>
  </div>;

  return <form className={`setup-form ${compact ? "compact" : ""}`} data-state={state.kind} onSubmit={event => { event.preventDefault(); void (catalog ? create() : loadPlans()); }}>
    <div className="form-heading">
      <span><CloudArrowUp size={20} /></span>
      <div><h2>{t("onboarding.hetzner.title")}</h2><p>{t("onboarding.hetzner.summary")}</p></div>
    </div>
    {tokenField}
    {catalog && <>
      <Field label={t("onboarding.hetzner.location")}>
        <select value={location} disabled={busy} onChange={event => chooseLocation(event.target.value)}>
          {catalog.locations.map(item => <option key={item.name} value={item.name}>{t("onboarding.hetzner.locationOption", { city: item.city, country: countryName(item.country), name: item.name })}</option>)}
        </select>
      </Field>
      <Field label={t("onboarding.hetzner.serverType")}>
        <select className="hetzner-plan-select" value={serverType} disabled={busy} onChange={event => setServerType(event.target.value)}>
          {plans.map(type => <option key={type.name} value={type.name}>{t("onboarding.hetzner.typeOption", {
            name: type.name, architecture: type.architecture, cores: type.cores, memory: type.memory_gb, disk: type.disk_gb,
            price: money(type.prices.find(item => item.location === location)?.total_monthly ?? "", catalog.currency),
          })}</option>)}
        </select>
      </Field>
      {price && <p className="hetzner-price" role="status"><ShieldCheck size={18} aria-hidden="true" /><span>{price.ipv4_monthly
        ? t("onboarding.hetzner.price", { total: money(price.total_monthly, catalog.currency), server: money(price.server_monthly, catalog.currency), ipv4: money(price.ipv4_monthly, catalog.currency) })
        : t("onboarding.hetzner.priceNoIpv4", { total: money(price.total_monthly, catalog.currency) })}</span></p>}
    </>}
    {errorBox}
    <button className="primary-button" type="submit" disabled={busy || !token || (catalog !== null && !price)}>
      {state.kind === "loadingPlans" ? <><ArrowClockwise className="spin" size={17} />{t("onboarding.hetzner.loading")}</> : catalog && price
        ? t("onboarding.hetzner.create", { total: money(price.total_monthly, catalog.currency) })
        : t("onboarding.hetzner.loadPlans")}
    </button>
  </form>;
}
