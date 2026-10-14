import { ReleaseUpdateSession } from "./features/settings/ReleaseUpdateSession";
import { AndroidOperation } from "./components/AndroidOperation";
import { useAndroidBack } from "./hooks/useAndroidBack";
import { describeConnection } from "./features/connection/connectionState";
import { DesktopTitleBar } from "./components/DesktopTitleBar";
import { ServerCollection } from "./features/servers/ServerCollection";
import type { SettingsCategory } from "./features/settings/SettingsLayout";
import { DialogContent } from "./components/DialogContent";
import { PreferencesProvider } from "./features/settings/PreferencesProvider";
const GeneralSettings = lazy(() => import("./features/settings/GeneralSettings").then(m => ({ default: m.GeneralSettings })));
import { usePageTransition } from "./hooks/usePageTransition";
import { usePageNavigation } from "./hooks/usePageNavigation";
import { confirmNavigation } from "./lib/navigationGuard";
import { useDesktopTray, type DesktopNavigation } from "./hooks/useDesktopTray";
import { favoritesFirst, useDesktopStatus } from "./hooks/useDesktopStatus";
import { Navigation } from "./components/Navigation";
import { InfrastructureArt } from "./components/InfrastructureArt";
import * as Dialog from "@radix-ui/react-dialog";
import {
  ArrowClockwise,
  CaretRight,
  Database,
  GearSix,
  LockKey,
  Plus,
  ShieldCheck,
} from "@phosphor-icons/react";
import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { api } from "./api";
import { t } from "./i18n";
import { type ClientPlatform, type ServerProfile } from "./types";
import { Brand, PrivacyPromises } from "./components/Brand";
import {
  InlineError,
  LoadingScreen,
  PlatformUnavailable,
} from "./components/ui";
const AddServerFlow = lazy(() => import("./features/onboarding/AddServerFlow").then(m => ({ default: m.AddServerFlow })));
const ServerWorkspace = lazy(() => import("./features/connection/ServerWorkspace").then(m => ({ default: m.ServerWorkspace })));
const ReleaseUpdateDialog = lazy(() => import("./features/settings/ReleaseUpdateDialog").then(m => ({ default: m.ReleaseUpdateDialog })));

export default function App() {
  useAndroidBack();
  return (
    <PreferencesProvider>
      <ReleaseUpdateSession><Suspense fallback={<LoadingScreen />}><AppContent /></Suspense></ReleaseUpdateSession>
    </PreferencesProvider>
  );
}

function AppContent() {
  const [clientPlatform, setClientPlatform] = useState<ClientPlatform | null>(
    null,
  );
  const [platformError, setPlatformError] = useState<string | null>(null);
  const [initializationAttempt, setInitializationAttempt] = useState(0);
  const [page, setPage, detail, goBack] = usePageNavigation();
  const pageContent = usePageTransition<HTMLDivElement>(page);
  const [servers, setServers] = useState<ServerProfile[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [settingsCategory, setSettingsCategory] =
    useState<SettingsCategory>("general");
  const [addMode, setAddMode] = useState<"provision" | "backup" | undefined>();
  const [addOpen, setAddOpen] = useState(false);
  const [appSettingsOpen, setAppSettingsOpen] = useState(false);
  const [trayRequest, setTrayRequest] = useState<DesktopNavigation | null>(
    null,
  );
  const [releaseUpdateOpen, setReleaseUpdateOpen] = useState(false);
  const { localStatus, serverStatus, refreshStatus, freshness, trafficUpdates } =
    useDesktopStatus(clientPlatform, setServers);

  const loadServers = useCallback(async () => {
    try {
      const profiles = favoritesFirst(await api.listServers());
      setServers(profiles);
      setSelectedId((current) =>
        profiles.some((profile) => profile.id === current)
          ? current
          : (profiles[0]?.id ?? null),
      );
      setLoadError(null);
    } catch {
      setLoadError(t("app.errors.profiles"));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setPlatformError(null);
    void api
      .clientPlatform()
      .then((platform) => {
        if (!active) return;
        if (platform !== "desktop" && platform !== "android") {
          throw new Error("Unsupported client platform");
        }
        setClientPlatform(platform);
        if (platform === "desktop" || platform === "android") {
          void loadServers();
        } else {
          setLoading(false);
        }
      })
      .catch(() => {
        if (!active) return;
        setPlatformError(t("app.errors.platform"));
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [loadServers, initializationAttempt]);

  const selected = useMemo(
    () =>
      servers.find((server) => server.id === selectedId) ?? servers[0] ?? null,
    [selectedId, servers],
  );
  const releaseInstallReady =
    localStatus.state === "disconnected" &&
    !localStatus.kill_switch_enabled &&
    !localStatus.auto_reconnect_enabled;

  const handleServerAdded = async (profile: ServerProfile) => {
    await loadServers();
    setSelectedId(profile.id);
    setAddOpen(false);
    setPage("home");
  };
  const openSettings = (category: SettingsCategory) => {
    setSettingsCategory(category);
    setPage("settings", clientPlatform === "android" ? category : undefined);
  };

  useDesktopTray(
    clientPlatform === "desktop" && !loading,
    selected?.id ?? null,
    (request) => {
      if (request.server_id) {
        if (!servers.some((server) => server.id === request.server_id)) {
          setLoadError(t("app.errors.trayServer"));
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
          setSettingsCategory("general");
          setPage("settings");
          if (!servers.length) setAppSettingsOpen(true);
          break;
        case "connection":
          setSettingsCategory("connection");
          setPage("settings");
          break;
        case "diagnostics":
          setSettingsCategory("maintenance");
          setPage("settings");
          setTrayRequest(request);
          break;
        case "component_update":
          setSettingsCategory("connection");
          setPage("settings");
          setTrayRequest(request);
          break;
      }
    },
  );

  if (loading)
    return (
      <>
        {clientPlatform === "desktop" && <DesktopTitleBar />}
        <LoadingScreen />
      </>
    );

  if (platformError || clientPlatform === null) {
    return (
      <PlatformUnavailable
        onRetry={() => setInitializationAttempt((value) => value + 1)}
        message={
          platformError ?? t("app.errors.platform")
        }
      />
    );
  }


  if (servers.length === 0) {
    return (
      <>
        {clientPlatform === "desktop" && <DesktopTitleBar />}
        <main className="onboarding-shell">
          <AndroidOperation />
          <header className="onboarding-header">
            <Brand compact={false} />
            <div className="onboarding-actions">
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
                    <GeneralSettings platform={clientPlatform} onCheckUpdates={() => setReleaseUpdateOpen(true)} />
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
            <h1>{clientPlatform === "android" ? <>{t("app.onboarding.headlineFirst")}<br />{t("app.onboarding.headlineSecond")}</> : t("app.onboarding.desktopTitle")}</h1>
            {clientPlatform !== "android" && <InfrastructureArt />}
            <p>
              {t(clientPlatform === "android" ? "app.onboarding.androidIntro" : "app.onboarding.desktopIntro")}
            </p>
            {clientPlatform !== "android" && <PrivacyPromises />}
          </section>
          <section
            className="onboarding-form-wrap"
            aria-label={t("app.onboarding.firstServer")}
          >
            {loadError ? (
              <div className="local-data-error">
                <LockKey size={28} weight="duotone" />
                <h2>{t("app.onboarding.storeTitle")}</h2>
                <p>{t("app.onboarding.storeHelp")}</p>
                <InlineError message={loadError} />
                <button className="secondary-button" onClick={() => { setLoading(true); void loadServers(); }}>{t("common.action.retry")}</button>
              </div>
            ) : (
              <AddServerFlow onAdded={handleServerAdded} />
            )}
          </section>
        </main>
        <ReleaseUpdateDialog
          open={releaseUpdateOpen}
          onOpenChange={setReleaseUpdateOpen}
          installationReady={releaseInstallReady}
          onReviewPrerequisites={() => { setPage("home"); setSettingsCategory("connection"); }}
        />
      </>
    );
  }

  return (
    <div className="app-shell">
      {clientPlatform === "desktop" && <DesktopTitleBar />}
      <a className="skip-link" href="#main-content">
        {t("app.skipToContent")}
      </a>
      <aside className="sidebar">
        <Brand compact />
        <Navigation page={page} onChange={setPage} />
        <div className="sidebar-heading">
          <span>{t("app.sidebar.servers")}</span>
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
        <nav className="server-list" aria-label={t("app.sidebar.serverList")}>
          {servers.map((server) => {
            const connected =
              localStatus.server_id === server.id &&
              localStatus.state === "connected";
            return (
              <button
                key={server.id}
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
                  <strong>{server.name}</strong>
                  <small>
                    {describeConnection(localStatus, server.id, null).status}
                  </small>
                </span>
                <CaretRight size={14} />
              </button>
            );
          })}
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
            <ServerWorkspace
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
              category={clientPlatform === "android" && page === "settings" && detail ? detail as SettingsCategory : settingsCategory}
              onCategoryChange={clientPlatform === "android" ? openSettings : setSettingsCategory}
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
            />
          ) : null}
        </div>
      </main>
      <Navigation page={page} onChange={setPage} mobile />
      <ReleaseUpdateDialog
        open={releaseUpdateOpen}
        onOpenChange={setReleaseUpdateOpen}
        installationReady={releaseInstallReady}
          onReviewPrerequisites={() => { setPage("home"); setSettingsCategory("connection"); }}
      />
    </div>
  );
}
