use super::*;
use sirinvpn_protocol::DEFAULT_TLS_LIKE_PORT;
mod ipv6_only;
mod split_dns;

mod maintenance_recovery;
mod ssh_output;

fn install_script(
    request: &InstallRequest,
    discovery: &ServerDiscovery,
    binary: &str,
    owner: &str,
    nonce: &str,
    transaction: InstallTransaction<'_>,
) -> String {
    crate::install_script::install_script(
        request,
        discovery,
        binary,
        owner,
        nonce,
        transaction,
        &release_guard::PreparedArtifact {
            bytes: Vec::new(),
            sha256: "0".repeat(64),
            state_guard: "true".to_owned(),
            preserves_signed_release: false,
        },
    )
}

/// A Debian 13 VPS on eth0 with the given address families.
fn stack(ipv4_available: bool, ipv6_available: bool) -> ServerDiscovery {
    ServerDiscovery {
        os_id: "debian".into(),
        os_version: "13".into(),
        architecture: "x86_64".into(),
        default_interface: "eth0".into(),
        ipv6_default_interface: ipv6_available.then(|| "eth0".into()),
        ssh_server_port: 22,
        ssh_local_address: None,
        ipv4_available,
        ipv6_available,
        nftables_available: true,
        wireguard_available: true,
        unbound_installed: false,
        sirinvpn_installed: false,
    }
}

fn script_transaction(
    owner_client_tunnel_address: &str,
    ipv6_tunnel_enabled: bool,
    restore_snapshot: bool,
) -> InstallTransaction<'static> {
    InstallTransaction {
        endpoint_discovery_port: None,
        expected_profile: None,
        restore_snapshot: restore_snapshot.then_some(&[]),
        owner_client_tunnel_address: owner_client_tunnel_address.parse().unwrap(),
        ipv6_tunnel_enabled,
    }
}

mod repair_requires_intact_matching_identity_and_compatible_state;
mod script_has_scoped_firewall_ownership_and_docker_interop;
mod server_restore_is_profile_bound_stdin_only_and_guarded_before_identity_replacement;
mod shell_quoting_does_not_allow_substitution;
mod uninstall_restores_original_forwarding;
