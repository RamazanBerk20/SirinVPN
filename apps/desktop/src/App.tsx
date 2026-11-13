import { ReleaseUpdateSession } from "./features/settings/ReleaseUpdateSession";
import { AndroidOperation } from "./components/AndroidOperation";
import { ToastRegion } from "./components/Toasts";
import { useAndroidBack } from "./hooks/useAndroidBack";
import { describeConnection } from "./features/connection/connectionState";
import { usePendingCommand } from "./features/connection/connectionCommands";
import { connectionView, type ConnectionView } from "./features/connection/connectionView";
import { DesktopTitleBar } from "./components/DesktopTitleBar";
import { SEARCH_THRESHOLD, ServerCollection } from "./features/servers/ServerCollection";
import type { SettingsCategory } from "./features/settings/SettingsLayout";
import type { SetupNext } from "./features/onboarding/SetupFlow";
import { DialogContent } from "./components/DialogContent";
import { PreferencesProvider } from "./features/settings/PreferencesProvider";
import { LanguagePicker } from "./features/settings/LanguagePicker";
const GeneralSettings = lazy(() => import("./features/settings/GeneralSettings").then(m => ({ default: m.GeneralSettings })));
import { usePageTransition } from "./hooks/usePageTransition";
import { usePageNavigation } from "./hooks/usePageNavigation";
import { confirmNavigation } from "./lib/navigationGuard";
import { useDesktopTray, type DesktopNavigation } from "./hooks/useDesktopTray";
import { favoritesFirst, useDesktopStatus } from "./hooks/useDesktopStatus";
import { useScheduledVpsBackups } from "./features/settings/vpsBackupSchedules";
import { Navigation } from "./components/Navigation";
import { InfrastructureArt } from "./components/InfrastructureArt";
import * as Dialog from "@radix-ui/react-dialog";
import {
  ArrowClockwise,
  Database,
  GearSix,
  Plus,
  ShieldCheck,
} from "@phosphor-icons/react";
import { lazy, Suspense, useCallback, useEffect, useReducer, useState, type SetStateAction } from "react";
import { api } from "./api";
import { isAndroid, setDemo } from "./platform";
import { foldText, t } from "./i18n";
import { type ServerProfile } from "./types";
import { bootPlatform, bootReducer, initialBoot } from "./appBoot";
import { Brand, PrivacyPromises } from "./components/Brand";
import {
  InlineError,
  LoadingScreen,
  PlatformUnavailable,
  StartupProblem,
} from "./components/ui";
const AddServerFlow = lazy(() => import("./features/onboarding/AddServerFlow").then(m => ({ default: m.AddServerFlow })));
const ServerWorkspace = lazy(() => import("./features/connection/ServerWorkspace").then(m => ({ default: m.ServerWorkspace })));
const ReleaseUpdateDialog = lazy(() => import("./features/settings/ReleaseUpdateDialog").then(m => ({ default: m.ReleaseUpdateDialog })));

/** The sidebar names a command the user sent before the tunnel reports it. */
function sidebarStatus(view: ConnectionView): string | null {
  if (view.phase === "stopping") return t("home.status.disconnecting");
  return view.phase === "starting" && view.by === "user" ? t("home.status.connecting") : null;
}

const noServers: ServerProfile[] = [];
/** Lazily loaded parts show this in place; the full-screen loader is for boot only, so a visible screen never disappears. */
function InlineLoading() {
  return <p className="inline-loading" role="status">{t("common.state.loading")}</p>;
}

export default function App() {
  useAndroidBack();
  return (
    <PreferencesProvider>
      <ReleaseUpdateSession><Suspense fallback={<LoadingScreen />}><AppContent /></Suspense></ReleaseUpdateSession>
    </PreferencesProvider>
  );
}

function AppContent() {
  const [boot, dispatch] = useReducer(bootReducer, initialBoot);
  const [initializationAttempt, setInitializationAttempt] = useState(0);
  const clientPlatform = bootPlatform(boot);
  const servers = boot.kind === "ready" ? boot.servers : noServers;
  const [page, setPage, detail, goBack] = usePageNavigation();
  const pageContent = usePageTransition<HTMLDivElement>(page);
  const pendingCommand = usePendingCommand();
  const [settingsCategory, setSettingsCategory] =
    useState<SettingsCategory>("general");
  const [addMode, setAddMode] = useState<"provision" | "backup" | undefined>();
  const [addOpen, setAddOpen] = useState(false);
  const [appSettingsOpen, setAppSettingsOpen] = useState(false);
  const [trayRequest, setTrayRequest] = useState<DesktopNavigation | null>(
    null,
  );
  const [releaseUpdateOpen, setReleaseUpdateOpen] = useState(false);
  const [serverQuery, setServerQuery] = useState("");
  const setServers = useCallback((update: SetStateAction<ServerProfile[]>) => dispatch({ type: "serversChanged", update }), []);
  const setSelectedId = useCallback((id: string) => dispatch({ type: "select", id }), []);
  const { localStatus, serverStatus, refreshStatus, freshness, trafficUpdates } =
    useDesktopStatus(clientPlatform, setServers);

  /** `select` picks a server once the list is read, such as the one just added. */
  const loadServers = useCallback(async (select?: string) => {
    try {
      dispatch({ type: "serversLoaded", servers: favoritesFirst(await api.listServers()), select });
    } catch {
      dispatch({ type: "serversFailed" });
    }
  }, []);

  useEffect(() => {
    let active = true;
    dispatch({ type: "detect" });
    void api
      .clientPlatform()
      .then((platform) => {
        if (!active) return;
        if (platform !== "desktop" && platform !== "android") throw new Error("Unsupported client platform");
        dispatch({ type: "platformDetected", platform });
        void loadServers();
      })
      .catch(() => {
        if (active) dispatch({ type: "platformFailed" });
      });
    return () => {
      active = false;
    };
  }, [loadServers, initializationAttempt]);
  // Agents and UI tests read the boot phase from the document.
  useEffect(() => { document.documentElement.dataset.boot = boot.kind; }, [boot.kind]);

  const selected = boot.kind === "ready" ? boot.servers.find((server) => server.id === boot.selectedId) ?? null : null;
  const loadError = boot.kind === "ready" && boot.notice ? t(boot.notice === "profiles" ? "app.errors.profiles" : "app.errors.trayServer") : null;
  const releaseInstallReady =
    localStatus.state === "disconnected" &&
    !localStatus.kill_switch_enabled &&
    !localStatus.auto_reconnect_enabled;
  useScheduledVpsBackups(releaseInstallReady && servers.some((server) => server.role === "owner"));

  const openSettings = (category: SettingsCategory) => {
    // The category is part of the URL on both platforms, so Back returns to the previous tab.
    setSettingsCategory(category);
    setPage("settings", category);
  };
  /** `next` lands on the page the finished flow pointed at, such as Keys & recovery after setup. */
  const handleServerAdded = async (profile: ServerProfile, next?: SetupNext) => {
    await loadServers(profile.id);
    setAddOpen(false);
    if (next === "recovery") openSettings("recovery");
    else setPage("home");
  };

  useDesktopTray(
    clientPlatform === "desktop" && boot.kind !== "detecting",
    selected?.id ?? null,
    (request) => {
      if (request.server_id) {
        if (!servers.some((server) => server.id === request.server_id)) {
          dispatch({ type: "notice", notice: "trayServer" });
          return;
        }
      }
      // setPage skips the guard for an unchanged page, but a new server or settings category still unmounts views.
      const changesServer = Boolean(request.server_id) && request.server_id !== selected?.id;
      if ((request.destination !== "add_server" || changesServer) && !confirmNavigation()) return;
      if (request.server_id) setSelectedId(request.server_id);
      switch (request.destination) {
        case "home":
          setPage("home");
          break;
        case "servers":
          setPage("servers");
          break;
        case "add_server":
          setAddMode("provision");
          setAddOpen(true);
          break;
        case "settings":
          openSettings("general");
          if (!servers.length) setAppSettingsOpen(true);
          break;
        case "connection":
          openSettings("connection");
          break;
        case "diagnostics":
          openSettings("maintenance");
          setTrayRequest(request);
          break;
        case "component_update":
          openSettings("connection");
          setTrayRequest(request);
          break;
      }
    },
  );

  // The desktop window is frameless: before the platform is known, only the custom title bar can move or close it.
  if (boot.kind === "detecting")
    return (
      <>
        {!isAndroid && <DesktopTitleBar />}
        <LoadingScreen />
      </>
    );

  if (boot.kind === "platformFailed" || clientPlatform === null) {
    return (
      <>
      {!isAndroid && <DesktopTitleBar />}
      <PlatformUnavailable
        onRetry={() => setInitializationAttempt((value) => value + 1)}
        message={
          t("app.errors.platform")
        }
      />
      </>
    );
  }


  // Saved servers that can't be read are a problem to fix, not a first launch: no setup pitch, no demo.
  if (boot.kind === "storeFailed") {
    return (
      <>
        {clientPlatform === "desktop" && <DesktopTitleBar />}
        <StartupProblem
          title={t("app.onboarding.storeTitle")}
          message={t("app.errors.profiles")}
          help={t(clientPlatform === "android" ? "app.onboarding.storeHelpAndroid" : "app.onboarding.storeHelpDesktop")}
          onRetry={() => { dispatch({ type: "reload" }); void loadServers(); }}
        >
          {/* A locked keyring must not also lock out a fix that comes as an update. */}
          {clientPlatform === "desktop" && <button className="text-button" type="button" onClick={() => setReleaseUpdateOpen(true)}>{t("app.onboarding.checkUpdates")}</button>}
        </StartupProblem>
        {clientPlatform === "desktop" && <Suspense fallback={null}><ReleaseUpdateDialog
          open={releaseUpdateOpen}
          onOpenChange={setReleaseUpdateOpen}
          installationReady={releaseInstallReady}
          onReviewPrerequisites={() => setReleaseUpdateOpen(false)}
        /></Suspense>}
        <ToastRegion />
      </>
    );
  }

  if (boot.kind === "empty") {
    return (
      <>
        {clientPlatform === "desktop" && <DesktopTitleBar />}
        <main className="onboarding-shell" data-state={boot.kind}>
          <AndroidOperation />
          <header className="onboarding-header">
            <Brand compact={false} />
            <div className="onboarding-actions">
              <LanguagePicker compact />
              <Dialog.Root
                open={appSettingsOpen}
                onOpenChange={setAppSettingsOpen}
              >
                <Dialog.Trigger asChild>
                  <button className={clientPlatform === "android" ? "icon-button" : "secondary-button"} aria-label={t("app.onboarding.settings")}>
                    <GearSix size={22} /> {clientPlatform !== "android" && t("app.onboarding.settings")}
                  </button>
                </Dialog.Trigger>
                <Dialog.Portal>
                  <Dialog.Overlay className="dialog-overlay" />
                  <DialogContent className="dialog-content preferences-dialog" heading={t("app.onboarding.settings")} description={t("app.onboarding.settingsDescription")}>
                    <Suspense fallback={<InlineLoading />}><GeneralSettings platform={clientPlatform} onCheckUpdates={() => setReleaseUpdateOpen(true)} /></Suspense>
                  </DialogContent>
                </Dialog.Portal>
              </Dialog.Root>
              {clientPlatform !== "android" && <button
                className="secondary-button"
                type="button"
                onClick={() => setReleaseUpdateOpen(true)}
              >
                <ArrowClockwise size={17} /> {t("app.onboarding.checkUpdates")}
              </button>}
            </div>
          </header>
          <section className="onboarding-copy">
            <p className="section-label">{t("app.onboarding.welcome")}</p>
            <h1>{t("app.onboarding.headlineFirst")}<br />{t("app.onboarding.headlineSecond")}</h1>
            {clientPlatform !== "android" && <InfrastructureArt />}
            <p>
              {t(clientPlatform === "android" ? "app.onboarding.androidIntro" : "app.onboarding.desktopIntro")}
            </p>
            {clientPlatform !== "android" && <PrivacyPromises />}
            {clientPlatform !== "android" && <div className="onboarding-demo">
              <p>{t("help.demo.enterHint")}</p>
              <button className="secondary-button" type="button" onClick={() => setDemo(true)}>{t("help.demo.enter")}</button>
            </div>}
          </section>
          <section
            className="onboarding-form-wrap"
            aria-label={t("app.onboarding.firstServer")}
          >
            <Suspense fallback={<InlineLoading />}><AddServerFlow onAdded={handleServerAdded} /></Suspense>
          </section>
          {/* On a phone the real ways in come first; the demo is a quiet way to look around. */}
          {clientPlatform === "android" && <div className="onboarding-demo mobile-demo">
            <button className="text-button" type="button" onClick={() => setDemo(true)}>{t("help.demo.enter")}</button>
            <p>{t("help.demo.enterHint")}</p>
          </div>}
        </main>
        <Suspense fallback={null}><ReleaseUpdateDialog
          open={releaseUpdateOpen}
          onOpenChange={setReleaseUpdateOpen}
          installationReady={releaseInstallReady}
          onReviewPrerequisites={() => { setPage("home"); setSettingsCategory("connection"); }}
        /></Suspense>
        <ToastRegion />
      </>
    );
  }

  const listedServers = servers.length < SEARCH_THRESHOLD ? servers
    : servers.filter((server) => foldText(`${server.name} ${server.endpoint.host}`).includes(foldText(serverQuery.trim())));
  return (
    <div className="app-shell" data-state={boot.kind}>
      {clientPlatform === "desktop" && <DesktopTitleBar />}
      <a className="skip-link" href="#main-content">
        {t("app.skipToContent")}
      </a>
      <aside className="sidebar">
        <Brand compact />
        <Navigation page={page} onChange={setPage} />
        <div className="sidebar-heading">
          <span>{t("app.sidebar.servers")}</span>
          {/* The list below switches servers; renaming, favourites and maintenance live on the Servers page. */}
          <button className="text-button sidebar-manage" type="button" aria-label={t("app.sidebar.manageLabel")}
            aria-current={page === "servers" ? "page" : undefined} onClick={() => setPage("servers")}>
            {t("app.sidebar.manage")}
          </button>
          <Dialog.Root open={addOpen} onOpenChange={(open) => { if (open || confirmNavigation()) setAddOpen(open); }}>
            <Dialog.Trigger asChild>
              <button
                className="icon-button"
                aria-label={t("servers.add")}
                onClick={() => setAddMode(undefined)}
              >
                <Plus size={18} weight="bold" />
              </button>
            </Dialog.Trigger>
            <Dialog.Portal>
              <Dialog.Overlay className="dialog-overlay" />
              <DialogContent className="dialog-content setup-dialog" heading={t("app.addServer.title")} description={t("app.addServer.description")}>
                <AddServerFlow
                  onAdded={handleServerAdded}
                  compact
                  initialMode={addMode}
                />
              </DialogContent>
            </Dialog.Portal>
          </Dialog.Root>
        </div>
        {/* The sidebar is the one switcher, so a long list gets the same search as the Servers page. */}
        {servers.length >= SEARCH_THRESHOLD && <input className="sidebar-search" type="search" value={serverQuery}
          aria-label={t("servers.search.label")} placeholder={t("servers.search.placeholder")} onChange={(event) => setServerQuery(event.target.value)} />}
        <nav className="server-list" aria-label={t("app.sidebar.serverList")}>
          {listedServers.map((server) => {
            const connected =
              localStatus.server_id === server.id &&
              localStatus.state === "connected";
            return (
              <button
                key={server.id}
                title={server.name}
                aria-current={selected?.id === server.id || undefined}
                className={`server-row ${selected?.id === server.id ? "selected" : ""}`}
                onClick={() => {
                  setSelectedId(server.id);
                  setPage("home");
                }}
              >
                <span className={`server-glyph ${connected ? "online" : ""}`}>
                  <Database size={18} weight="duotone" />
                </span>
                <span>
                  <strong dir="auto">{server.name}</strong>
                  <small>
                    {sidebarStatus(connectionView(localStatus, server.id, pendingCommand)) ?? describeConnection(localStatus, server.id, null).status}
                  </small>
                </span>
              </button>
            );
          })}
          {!listedServers.length && <p className="sidebar-empty" role="status">{t("servers.search.empty")}</p>}
        </nav>
        <div className="sidebar-foot">
          <ShieldCheck size={17} weight="duotone" />
          <span>{t("app.sidebar.privacy")}</span>
        </div>
      </aside>

      <main className="workspace" id="main-content">
        <AndroidOperation />
        <div ref={pageContent} className="page-content">
          {page === "servers" && (
            <ServerCollection
              servers={servers}
              selectedId={selected?.id}
              local={localStatus}
              onOpen={(id) => {
                setSelectedId(id);
                setPage("home");
              }}
              onInspect={(id) => {
                setSelectedId(id);
                openSettings("maintenance");
              }}
              onAdd={() => {
                setAddMode(undefined);
                setAddOpen(true);
              }}
              onChanged={loadServers}
            />
          )}
          {loadError ? <InlineError message={loadError} /> : null}
          {selected ? (
            <Suspense fallback={<InlineLoading />}><ServerWorkspace
              key={selected.id}
              onTrayRequestHandled={() => setTrayRequest(null)}
              trayRequest={
                trayRequest?.server_id === selected.id ? trayRequest : null
              }
              view={page}
              detail={detail}
              onBack={goBack}
              onNavigate={setPage}
              onOpenSettings={openSettings}
              onCheckUpdates={() => setReleaseUpdateOpen(true)}
              profile={selected}
              freshness={freshness}
              category={page === "settings" && detail ? detail as SettingsCategory : settingsCategory}
              onCategoryChange={openSettings}
              onRestoreDevice={() => {
                setAddMode("backup");
                setAddOpen(true);
              }}
              localStatus={localStatus}
              trafficUpdates={trafficUpdates}
              serverStatus={
                localStatus.server_id === selected.id ? serverStatus : null
              }
              onRefresh={refreshStatus}
              onAccessChanged={async () => {
                await loadServers();
                await refreshStatus();
              }}
              onRemoved={loadServers}
              servers={servers}
              onSelectServer={setSelectedId}
              onAddServer={() => {
                setAddMode(undefined);
                setAddOpen(true);
              }}
            /></Suspense>
          ) : null}
        </div>
      </main>
      <Navigation page={page} onChange={setPage} mobile />
      <Suspense fallback={null}><ReleaseUpdateDialog
        open={releaseUpdateOpen}
        onOpenChange={setReleaseUpdateOpen}
        installationReady={releaseInstallReady}
          onReviewPrerequisites={() => { setPage("home"); setSettingsCategory("connection"); }}
      /></Suspense>
      <ToastRegion />
    </div>
  );
}
