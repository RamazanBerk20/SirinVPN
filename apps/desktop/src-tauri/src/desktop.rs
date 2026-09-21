
mod app_notifications;
mod app_preferences;
mod connection_preferences;
mod diagnostics;
mod invitation_preview;
mod management_session;
mod management_types;
use app_preferences::{get_app_preferences, set_app_preferences};
use app_preferences::{request_notification_permission, test_notification};
use connection_preferences::{get_connection_preferences, set_connection_preferences};
use management_types::*;
mod connection_controller;
mod connection_notifications;
mod desktop_lifecycle;
#[cfg_attr(windows, path = "desktop_startup_windows.rs")]
mod desktop_startup;
mod desktop_tray;
mod local_component;
mod wifi_automation;

mod command_types;
use command_types::*;
mod provisioning;
mod server_preflight;
mod ssh_login;
mod ssh_trust;
mod vps_baseline;
mod vps_release;
use provisioning::*;
mod backups;
use backups::*;
mod endpoints;
use endpoints::*;
mod connection;
mod connection_policy;
mod server_status_stream;
use connection::*;
mod local_status_stream;
mod management;
use management::*;
mod member_lifecycle;
use member_lifecycle::*;
mod recovery;
use recovery::*;
mod identity;
use identity::*;
mod application_routing;
#[cfg_attr(windows, path = "helper_windows.rs")]
mod helper;
use helper::*;

#[cfg_attr(windows, path = "release_update_windows.rs")]
mod release_update;
mod release_update_status;

use anyhow::Result;
use anyhow::{anyhow, bail};
use qrcode::{EcLevel, QrCode, render::svg};
use release_update::{
    check_release_update, discard_release_update, get_release_update_status,
    install_release_update, rollback_release_update,
};
use serde::{Deserialize, Serialize};
use sirinvpn_core::{
    ClientPaths, EndpointTransitionCode, KeyRotationResult, NetworkContext,
    RotationConnectionPolicy, SecretIdentity, SecretStore, apply_endpoint_transition,
    create_endpoint_transition, has_pending_key_rotation, publish_endpoint_transition,
    rotate_current_device_keys_with_policy,
};
use sirinvpn_core::{
    DecodedInvitation, InvitationDraft, InvitationTarget, ManagementClient, ManagementError,
};
use sirinvpn_installer::{
    InstallRequest, Provisioner, SshAuthentication, SshTarget, UninstallRequest,
};
use sirinvpn_installer::{
    RepairRequest, ServerBackupOutcome, ServerBackupRequest, ServerRestoreOutcome,
    ServerRestoreRequest, new_identity_for_server,
};
use sirinvpn_protocol::{
    ConnectionState, NetworkProfile, PrivateDnsRecord, ServerEndpoint, ServerId, ServerProfile,
    ServerStatus, ipv6_tunnel_address, validate_dns_upstream, validate_private_dns_records,
};
use sirinvpn_protocol::{
    CurrentConfiguration, DeviceId, DiagnosticReport, InvitationId, MemberId, MembershipSnapshot,
    PortForwardCreateRequest,
};
use sirinvpn_protocol::{DnsUpstream, ServerRole, TransportKind, TransportPreference};
use sirinvpn_transport::{AutomaticAttempt, establish_automatic};
use sirinvpn_transport::{TransportEngine, TransportSelection};
use sirinvpn_tunnel_model::{
    LocalTunnelStatus, TunnelConnectRequest, TunnelRoutingMode, TunnelRoutingPolicy,
    automatic_reconnect_candidates,
};
use std::path::Path;
use std::{env, net::IpAddr, path::PathBuf};
use tauri::State;
use zeroize::{Zeroize, Zeroizing};

struct AppState {
    paths: ClientPaths,
}

#[tauri::command]
fn client_platform() -> &'static str {
    "desktop"
}

fn safe_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn run_inner() -> tauri::Result<()> {
    let paths = match ClientPaths::discover() {
        Ok(paths) => paths,
        Err(_) => std::process::exit(1),
    };
    let mut context = tauri::generate_context!();
    // Decide initial visibility from persisted preferences before showing the window.
    if let Some(window) = context
        .config_mut()
        .app
        .windows
        .iter_mut()
        .find(|window| window.label == "main")
    {
        window.visible = false;
        window.decorations = false;
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, args, _| {
            if !args.iter().any(|arg| arg == "--autostart") {
                desktop_lifecycle::show_main(app);
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .setup(desktop_lifecycle::setup)
        .manage(connection_notifications::ConnectionNotifications::default())
        .manage(AppState { paths })
        .manage(server_status_stream::StatusSubscriptions::default())
        .manage(release_update::ReleaseUpdateRuntime::default())
        .manage(vps_baseline::BaselineRuntime::default())
        .invoke_handler(tauri::generate_handler![
            application_routing::launch_vpn_application,
            local_status_stream::subscribe_local_status,
            local_status_stream::unsubscribe_local_status,
            local_component::local_component_update_status,
            local_component::install_local_vpn_component,
            client_platform,
            invitation_preview::preview_invitation,
            get_app_preferences,
            get_connection_preferences,
            set_connection_preferences,
            set_app_preferences,
            request_notification_permission,
            test_notification,
            get_release_update_status,
            rollback_release_update,
            check_release_update,
            install_release_update,
            discard_release_update,
            list_servers,
            update_server_presentation,
            probe_host_key,
            ssh_trust::inspect_ssh_host,
            ssh_trust::trust_ssh_host,
            ssh_login::get_ssh_login,
            ssh_login::save_ssh_login,
            ssh_login::forget_ssh_login,
            provision_server,
            server_preflight::inspect_server_network,
            vps_release::manage_vps_release,
            vps_baseline::prepare_vps_baseline,
            vps_baseline::install_vps_baseline,
            vps_baseline::discard_vps_baseline,
            remove_server,
            export_server_backup,
            import_server_backup,
            export_vps_backup,
            restore_vps_backup,
            uninstall_server,
            repair_server,
            create_endpoint_update,
            available_endpoint_update,
            apply_endpoint_update,
            publish_endpoint_update,
            connect_server,
            wifi_automation::get_wifi_policy,
            wifi_automation::set_wifi_policy,
            wifi_automation::trust_current_wifi,
            wifi_automation::forget_trusted_wifi,
            connection_policy::connect_server_with_policy,
            connection_policy::resume_server,
            connection_controller::reconnect_server,
            desktop_tray::navigation::desktop_navigation,
            desktop_tray::navigation::desktop_navigation_ack,
            desktop_tray::navigation::desktop_selection,
            current_network_profile,
            disconnect_server,
            local_status,
            server_status,
            server_status_stream::subscribe_server_status,
            server_status_stream::unsubscribe_server_status,
            server_configuration,
            run_diagnostics,
            membership,
            create_invitation,
            cancel_invitation,
            rename_device,
            revoke_device,
            update_device_peer_communication,
            create_port_forward,
            remove_port_forward,
            update_member_access,
            update_member_suspension,
            update_member_policy,
            recovery_settings,
            update_recovery_policy,
            create_recovery_key,
            revoke_recovery_key,
            preview_recovery_key,
            recover_owner_access,
            export_recovery_package,
            import_recovery_package,
            revoke_member_devices,
            transfer_ownership,
            key_rotation_pending,
            rotate_device_keys,
            join_server,
        ])
        .run(context)
}

pub fn run() {
    if run_inner().is_err() {
        std::process::exit(1);
    }
}
