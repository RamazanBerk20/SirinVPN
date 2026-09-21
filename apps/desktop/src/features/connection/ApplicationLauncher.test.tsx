import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApplicationLauncher } from "./ApplicationLauncher";
import { emptyLocalStatus } from "../../hooks/useDesktopStatus";
import { api } from "../../api";
import { open } from "@tauri-apps/plugin-dialog";
vi.mock("../../api", () => ({ api: { launchVpnApplication: vi.fn() } }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
const active = { ...emptyLocalStatus, server_id: "server", state: "connected" as const,
  routing_mode: "selected_applications" as const, application_routing_ready: true,
  application_routing_supported: true, supervisor_status_known: true };

describe("application routing launcher", () => {
  beforeEach(() => vi.clearAllMocks());
  afterEach(cleanup);
  it("requires a verified matching session before launching", () => {
    const view = render(<ApplicationLauncher serverId="server" local={{ ...active, application_routing_ready: false }} busy={false} />);
    fireEvent.change(screen.getByLabelText("Application executable"), { target: { value: "/usr/bin/example" } });
    expect((screen.getByRole("button", { name: "Launch in VPN" }) as HTMLButtonElement).disabled).toBe(true);
    view.rerender(<ApplicationLauncher serverId="server" local={{ ...active, server_id: "other" }} busy={false} />);
    expect((screen.getByRole("button", { name: "Launch in VPN" }) as HTMLButtonElement).disabled).toBe(true);
    expect(api.launchVpnApplication).not.toHaveBeenCalled();
  });
  it("passes literal arguments and distinguishes a finished command from a running app", async () => {
    vi.mocked(api.launchVpnApplication).mockResolvedValue({ process_id: null, completed: true });
    render(<ApplicationLauncher serverId="server" local={active} busy={false} />);
    fireEvent.change(screen.getByLabelText("Application executable"), { target: { value: "/usr/bin/example" } });
    fireEvent.change(screen.getByLabelText("One argument per line"), { target: { value: "--profile\na directory with spaces\n$(literal)" } });
    fireEvent.click(screen.getByRole("button", { name: "Launch in VPN" }));
    await waitFor(() => expect(api.launchVpnApplication).toHaveBeenCalledWith("server", "/usr/bin/example", ["--profile", "a directory with spaces", "$(literal)"]));
    expect((await screen.findByRole("status")).textContent).toContain("No running app was confirmed");
  });
  it("discards launch details and late results when another server is selected", async () => {
    let resolve!: (value: { process_id: number; completed: boolean }) => void;
    vi.mocked(api.launchVpnApplication).mockReturnValue(new Promise((done) => { resolve = done; }));
    const view = render(<ApplicationLauncher serverId="server" local={active} busy={false} />);
    fireEvent.change(screen.getByLabelText("Application executable"), { target: { value: "/usr/bin/example" } });
    fireEvent.click(screen.getByRole("button", { name: "Launch in VPN" }));
    view.rerender(<ApplicationLauncher serverId="other" local={active} busy={false} />);
    resolve({ process_id: 123, completed: false });
    await waitFor(() => expect((screen.getByLabelText("Application executable") as HTMLInputElement).value).toBe(""));
    expect(screen.queryByRole("status")).toBeNull();
  });
  it("uses Windows executable selection and explains its current-session protection", async () => {
    vi.mocked(open).mockResolvedValue("C:\\Apps\\client.exe");
    vi.mocked(api.launchVpnApplication).mockResolvedValue({ process_id: 42, completed: false });
    render(<ApplicationLauncher serverId="server" local={{ ...active, application_routing_backend: "windows_bind_redirect" }} busy={false} />);
    expect(screen.getByText(/Selected executables under your Windows account/).textContent).toContain("System DNS uses the VPS");
    expect(screen.getByText(/Disconnect releases their protection/)).toBeTruthy();
    expect(screen.queryByText(/optional kill switch off/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Choose application" }));
    await waitFor(() => expect((screen.getByLabelText("Application executable") as HTMLInputElement).value).toBe("C:\\Apps\\client.exe"));
    expect(open).toHaveBeenCalledWith(expect.objectContaining({ filters: [{ name: "Windows executable", extensions: ["exe"] }] }));
    fireEvent.click(screen.getByRole("button", { name: "Launch in VPN" }));
    expect((await screen.findByRole("status")).textContent).toContain("Disconnect clears");
  });
});
