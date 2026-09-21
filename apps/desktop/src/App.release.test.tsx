import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import App from "./App";

const apiMocks = vi.hoisted(() => ({
  getAppPreferences: vi.fn(),
  clientPlatform: vi.fn<() => Promise<"desktop">>(),
  checkReleaseUpdate: vi.fn(),
  installReleaseUpdate: vi.fn(),
  discardReleaseUpdate: vi.fn(),
  releaseUpdateStatus: vi.fn(),
  rollbackReleaseUpdate: vi.fn(),
  listServers: vi.fn(),
  localStatus: vi.fn(),
}));

const dialogMocks = vi.hoisted(() => ({
  open: vi.fn(),
  save: vi.fn(),
}));

vi.mock("./api", () => ({
  api: apiMocks,
}));

vi.mock("@tauri-apps/plugin-dialog", () => dialogMocks);

describe("Desktop release update boundary", () => {
  const candidate = {
    current_version: "0.1.0",
    release_version: "0.2.0",
    release_sequence: "2",
    channel: "stable" as const,
    security_update: true,
    trust_policy_sequence: "3",
    root_key_id_sha256: "a".repeat(64),
    release_key_id_sha256: "b".repeat(64),
    artifact_file_name: "SirinVPN_0.2.0_amd64.deb",
    artifact_target: "x86_64-unknown-linux-gnu",
    artifact_size_bytes: 12_345,
    artifact_sha256: "c".repeat(64),
    newer_than_running: true,
    debian_install_available: true,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    apiMocks.releaseUpdateStatus.mockResolvedValue({ installer_kind: "debian", rollback_version: null, baseline_required: false });
    apiMocks.getAppPreferences.mockResolvedValue({
      preferences: {
        start_on_login: false,
        launch_minimized: false,
        close_to_tray: false,
        notifications: false,
        animations: true,
      },
      startup_available: true,
      tray_available: true,
      notification_permission: "granted",
    });
    apiMocks.clientPlatform.mockResolvedValue("desktop");
    apiMocks.listServers.mockResolvedValue([]);
    apiMocks.localStatus.mockResolvedValue({
      state: "disconnected",
      interface_name: "sirinvpn0",
      server_id: null,
      rx_bytes: 0,
      tx_bytes: 0,
      ipv6_blocked: false,
      kill_switch_enabled: false,
      auto_reconnect_enabled: false,
      transport_fallback_enabled: false,
      routing_mode: "full_tunnel",
      allow_lan: false,
    });
    apiMocks.checkReleaseUpdate.mockResolvedValue(candidate);
    apiMocks.installReleaseUpdate.mockResolvedValue(candidate);
    apiMocks.discardReleaseUpdate.mockResolvedValue(undefined);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("keeps an Android install pending when its review closes and cancels only explicitly", async () => {
    const apk={...candidate,installer_kind:"android",android_install_available:true,debian_install_available:false};
    const status={installer_kind:"android",rollback_version:null,baseline_required:false,pending_version:null as string|null};
    apiMocks.releaseUpdateStatus.mockResolvedValue(status);
    apiMocks.checkReleaseUpdate.mockResolvedValue(apk);
    apiMocks.installReleaseUpdate.mockImplementationOnce(async()=>{
      apiMocks.releaseUpdateStatus.mockResolvedValue({...status,pending_version:apk.release_version});return apk;
    });
    apiMocks.discardReleaseUpdate.mockImplementationOnce(async()=>{apiMocks.releaseUpdateStatus.mockResolvedValue(status);});
    render(<App />);
    fireEvent.click(await screen.findByRole("button",{name:"Check for app updates"}));
    fireEvent.change(screen.getByLabelText(/^Release source/),{target:{value:["https","://updates.example/sirinvpn/"].join("")}});
    fireEvent.click(screen.getByRole("button",{name:"Check and verify release"}));
    fireEvent.click(await screen.findByRole("checkbox",{name:/I confirm installation/}));
    fireEvent.click(screen.getByRole("button",{name:"Install authenticated update"}));
    await screen.findByRole("heading",{name:"Android installer requested"});
    fireEvent.click(screen.getByRole("button",{name:"Close"}));
    expect(apiMocks.discardReleaseUpdate).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button",{name:"Check for app updates"}));
    fireEvent.click(await screen.findByRole("button",{name:"Cancel pending Android installation"}));
    await waitFor(()=>expect(apiMocks.discardReleaseUpdate).toHaveBeenCalledTimes(1));
    await waitFor(()=>expect(screen.queryByRole("button",{name:"Cancel pending Android installation"})).toBeNull());
  });

  it("never checks automatically and installs only after a separate confirmation", async () => {
    const source = ["https", "://updates.example/sirinvpn/stable/"].join("");
    render(<App />);

    const openUpdates = await screen.findByRole("button", {
      name: "Check for app updates",
    });
    expect(apiMocks.checkReleaseUpdate).not.toHaveBeenCalled();
    fireEvent.click(openUpdates);
    fireEvent.change(screen.getByLabelText(/^Release source/), {
      target: { value: `  ${source}  ` },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Check and verify release" }),
    );

    await waitFor(() =>
      expect(apiMocks.checkReleaseUpdate).toHaveBeenCalledWith(
        source,
        "stable",
      ),
    );
    expect(
      await screen.findByRole("heading", { name: "SirinVPN 0.2.0" }),
    ).toBeTruthy();
    expect(screen.getByText("x86_64-unknown-linux-gnu")).toBeTruthy();
    expect(screen.getByTitle("a".repeat(64))).toBeTruthy();
    const install = screen.getByRole("button", {
      name: "Install authenticated update",
    }) as HTMLButtonElement;
    expect(install.disabled).toBe(true);
    expect(apiMocks.installReleaseUpdate).not.toHaveBeenCalled();

    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /I confirm installation of this exact authenticated Debian package/,
      }),
    );
    expect(install.disabled).toBe(false);
    fireEvent.click(install);

    await waitFor(() =>
      expect(apiMocks.installReleaseUpdate).toHaveBeenCalledWith(true),
    );
    expect(
      await screen.findByRole("heading", {
        name: "SirinVPN 0.2.0 is installed",
      }),
    ).toBeTruthy();
    fireEvent.click(
      screen.getByRole("button", { name: "Close SirinVPN later" }),
    );
    await waitFor(() =>
      expect(apiMocks.discardReleaseUpdate).toHaveBeenCalledTimes(1),
    );
  });

  it("hands an authenticated Windows update to the installer while retaining protection", async () => {
    const windowsCandidate = { ...candidate, artifact_file_name: "SirinVPN_0.2.0_x64-setup.exe",
      artifact_target: "x86_64-pc-windows-msvc", debian_install_available: false,
      windows_install_available: true, installer_kind: "windows" as const };
    apiMocks.checkReleaseUpdate.mockResolvedValue(windowsCandidate);
    apiMocks.installReleaseUpdate.mockResolvedValue(windowsCandidate);
    apiMocks.localStatus.mockResolvedValue({ state: "connected", kill_switch_enabled: true,
      auto_reconnect_enabled: true, rx_bytes: 0, tx_bytes: 0, routing_mode: "full_tunnel" });
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Check for app updates" }));
    fireEvent.change(screen.getByLabelText(/^Release source/), {
      target: { value: ["https", "://updates.example/sirinvpn/stable/"].join("") },
    });
    fireEvent.click(screen.getByRole("button", { name: "Check and verify release" }));
    const confirmation = await screen.findByRole("checkbox", {
      name: /I confirm installation of this exact authenticated Windows package/,
    });
    expect((confirmation as HTMLInputElement).disabled).toBe(false);
    expect(screen.queryByText(/Disconnect SirinVPN and disable persistent protection/)).toBeNull();
    expect(apiMocks.installReleaseUpdate).not.toHaveBeenCalled();
    fireEvent.click(confirmation);
    fireEvent.click(screen.getByRole("button", { name: "Install authenticated update" }));
    expect(await screen.findByRole("heading", { name: "Windows installer opened" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: /is installed/ })).toBeNull();
    expect(apiMocks.installReleaseUpdate).toHaveBeenCalledWith(true);
  });

  it("keeps installation locked while the VPN is active", async () => {
    apiMocks.localStatus.mockResolvedValueOnce({
      state: "connected",
      interface_name: "sirinvpn0",
      server_id: null,
      rx_bytes: 0,
      tx_bytes: 0,
      ipv6_blocked: true,
      kill_switch_enabled: false,
      auto_reconnect_enabled: false,
      transport_fallback_enabled: false,
      routing_mode: "full_tunnel",
      allow_lan: false,
    });
    render(<App />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Check for app updates" }),
    );
    fireEvent.change(screen.getByLabelText(/^Release source/), {
      target: {
        value: ["https", "://updates.example/sirinvpn/stable/"].join(""),
      },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Check and verify release" }),
    );

    expect(
      await screen.findByText(
        /Disconnect SirinVPN and disable persistent protection/,
      ),
    ).toBeTruthy();
    expect(
      (
        screen.getByRole("checkbox", {
          name: /I confirm installation of this exact authenticated Debian package/,
        }) as HTMLInputElement
      ).disabled,
    ).toBe(true);
    expect(
      (
        screen.getByRole("button", {
          name: "Install authenticated update",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
    expect(apiMocks.installReleaseUpdate).not.toHaveBeenCalled();
  });
});
