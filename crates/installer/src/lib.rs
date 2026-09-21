#![forbid(unsafe_code)]

mod preflight;
mod transports;
pub use preflight::{
    AddressExposure, AssignedAddress, NetworkIssue, NetworkPreflight, RequiredPort,
};
pub use transports::TransportSetup;
use transports::*;
mod transaction;
use transaction::*;
mod ssh;
use ssh::*;
mod validation;
use validation::*;
mod verification;
use verification::*;
mod uninstall;
use uninstall::*;
mod dns;
use dns::*;
mod install_script;
use install_script::*;
mod install_failure;
mod maintenance;
mod release_guard;
mod release_update;
mod updates;
pub use release_update::{ServerReleaseAction, ServerReleaseRequest};
mod signed_baseline;
pub use signed_baseline::{
    SignedBaselineCandidate, SignedBaselineOutcome, SignedServerBundle, release_target,
};

use anyhow::{anyhow, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sirinvpn_core::{
    LocalIdentity, PublicIdentity, ServerBackupError, ServerBackupMetadata,
    read_encrypted_server_backup, validate_server_backup_password, write_encrypted_server_backup,
};
use sirinvpn_protocol::{
    DEFAULT_MANAGEMENT_PORT, DEFAULT_OBFUSCATED_UDP_PORT, DEFAULT_TCP_FALLBACK_PORT,
    DEFAULT_WIREGUARD_PORT, DOH_PROXY_PORT, DnsUpstream, FIRST_CLIENT_TUNNEL_ADDRESS,
    INTERFACE_NAME, MemberId, ObfuscatedUdpEndpoint, PrivateDnsRecord, SERVER_TUNNEL_ADDRESS,
    ServerEndpoint, ServerId, ServerProfile, ServerRole, TUNNEL_CIDR, TcpFallbackEndpoint,
    TlsLikeEndpoint, ipv6_tunnel_address, ipv6_tunnel_cidr, validate_dns_upstream, validate_host,
    validate_private_dns_records, validate_server_dns_configuration, validate_server_name,
};
use ssh2::Session;
use std::{
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_ARTIFACT_SIZE: u64 = 64 * 1024 * 1024;
const MAX_SERVER_BACKUP_SNAPSHOT_SIZE: usize = 2 * 1024 * 1024;
const MAX_SERVER_BACKUP_STDERR_SIZE: usize = 64 * 1024;
const SSH_OPERATION_TIMEOUT_MS: u32 = 30_000;
const INSTALL_OPERATION_TIMEOUT_MS: u32 = 10 * 60 * 1_000;
const MANAGED_SERVER_PATHS: &str = "usr/local/lib/sirinvpn/sirinvpn-server etc/sirinvpn etc/unbound/unbound.conf.d/sirinvpn.conf etc/systemd/system/unbound.service.d/sirinvpn.conf etc/sysctl.d/90-sirinvpn.conf etc/systemd/system/sirinvpn-network.service etc/systemd/system/sirinvpn-firewall.service etc/systemd/system/sirinvpn-doh.service etc/systemd/system/sirinvpn-server.service";

#[derive(Clone)]
pub enum SshAuthentication {
    Agent,
    Password(Zeroizing<String>),
    PrivateKey {
        path: PathBuf,
        passphrase: Option<Zeroizing<String>>,
    },
    PrivateKeyMemory {
        private_key_pem: Zeroizing<String>,
        passphrase: Option<Zeroizing<String>>,
    },
}

impl std::fmt::Debug for SshAuthentication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Agent => formatter.write_str("Agent"),
            Self::Password(_) => formatter.write_str("Password([REDACTED])"),
            Self::PrivateKey { path, .. } => formatter
                .debug_struct("PrivateKey")
                .field("path", path)
                .field("passphrase", &"[REDACTED]")
                .finish(),
            Self::PrivateKeyMemory { .. } => formatter
                .debug_struct("PrivateKeyMemory")
                .field("private_key_pem", &"[REDACTED]")
                .field("passphrase", &"[REDACTED]")
                .finish(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SshTarget {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub authentication: SshAuthentication,
    pub sudo_password: Option<Zeroizing<String>>,
    pub expected_host_key_sha256: Option<String>,
}

#[derive(Clone, Debug)]
pub enum ServerBinarySource {
    Signed(std::sync::Arc<SignedServerBundle>),
    Exact(PathBuf),
    ByArchitecture { x86_64: PathBuf, aarch64: PathBuf },
}

impl ServerBinarySource {
    pub fn by_architecture(x86_64: PathBuf, aarch64: PathBuf) -> Self {
        Self::ByArchitecture { x86_64, aarch64 }
    }

    fn path_for_architecture(&self, architecture: &str) -> Result<&Path, InstallerError> {
        match self {
            Self::Signed(_) => Err(InstallerError::InvalidInput(
                "authenticated server bytes must be loaded from their verified bundle".to_owned(),
            )),
            Self::Exact(path) => Ok(path),
            Self::ByArchitecture { x86_64, .. } if architecture == "x86_64" => Ok(x86_64),
            Self::ByArchitecture { aarch64, .. } if architecture == "aarch64" => Ok(aarch64),
            Self::ByArchitecture { .. } => Err(InstallerError::Incompatible(format!(
                "no packaged server artifact is available for VPS architecture {architecture}"
            ))),
        }
    }
}

impl From<PathBuf> for ServerBinarySource {
    fn from(path: PathBuf) -> Self {
        Self::Exact(path)
    }
}

impl From<&str> for ServerBinarySource {
    fn from(path: &str) -> Self {
        Self::Exact(PathBuf::from(path))
    }
}

#[derive(Clone, Debug)]
pub struct InstallRequest {
    pub server_id: ServerId,
    pub server_name: String,
    pub target: SshTarget,
    pub server_binary: ServerBinarySource,
    pub identity: PublicIdentity,
    pub identity_reference: String,
    pub transport: TransportSetup,
    pub dns_upstream: DnsUpstream,
    pub private_dns_records: Vec<PrivateDnsRecord>,
    pub replace_existing_installation: bool,
}

#[derive(Clone, Debug)]
pub struct UninstallRequest {
    pub server_id: ServerId,
    pub target: SshTarget,
    pub owner_certificate_pem: String,
}

#[derive(Clone, Debug)]
pub struct RepairRequest {
    pub profile: ServerProfile,
    pub target: SshTarget,
    pub server_binary: ServerBinarySource,
    pub identity: PublicIdentity,
    pub dns_upstream: Option<DnsUpstream>,
    pub private_dns_records: Option<Vec<PrivateDnsRecord>>,
    pub transport: Option<TransportSetup>,
}

pub struct ServerBackupRequest {
    pub profile: ServerProfile,
    pub target: SshTarget,
    pub server_binary: ServerBinarySource,
    pub identity: PublicIdentity,
    pub destination: PathBuf,
    pub password: Zeroizing<String>,
}

pub struct ServerRestoreRequest {
    pub profile: ServerProfile,
    pub target: SshTarget,
    pub server_binary: ServerBinarySource,
    pub identity: PublicIdentity,
    pub source: PathBuf,
    pub password: Zeroizing<String>,
    pub replace_existing_installation: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallPhase {
    Connecting,
    VerifyingHostKey,
    Authenticating,
    Discovering,
    CheckingCompatibility,
    Staging,
    InstallingDependencies,
    ConfiguringIdentity,
    ConfiguringNetwork,
    VerifyingServices,
    Committing,
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstallEvent {
    pub phase: InstallPhase,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServerDiscovery {
    pub os_id: String,
    pub os_version: String,
    pub architecture: String,
    pub default_interface: String,
    pub ipv6_default_interface: Option<String>,
    pub ssh_server_port: u16,
    pub ipv4_available: bool,
    pub ipv6_available: bool,
    pub nftables_available: bool,
    pub wireguard_available: bool,
    pub unbound_installed: bool,
    pub sirinvpn_installed: bool,
}

#[derive(Clone, Debug)]
pub struct InstallOutcome {
    pub network_preflight: NetworkPreflight,
    pub profile: ServerProfile,
    pub discovery: ServerDiscovery,
    pub events: Vec<InstallEvent>,
    pub artifact_sha256: String,
    pub dns_upstream: DnsUpstream,
    pub private_dns_records: Vec<PrivateDnsRecord>,
}

#[derive(Clone, Debug)]
pub struct RepairOutcome {
    pub network_preflight: NetworkPreflight,
    pub endpoint: ServerEndpoint,
    pub endpoint_generation: u64,
    pub alternate_endpoint_hosts: Vec<String>,
    pub endpoint_discovery_port: Option<u16>,
    pub events: Vec<InstallEvent>,
    pub artifact_sha256: String,
    pub ipv6_tunnel_enabled: bool,
    pub obfuscated_udp: Option<ObfuscatedUdpEndpoint>,
    pub tcp_fallback: Option<TcpFallbackEndpoint>,
    pub tls_like: Option<TlsLikeEndpoint>,
    pub dns_upstream: DnsUpstream,
    pub private_dns_records: Vec<PrivateDnsRecord>,
    pub wireguard_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ServerBackupOutcome {
    pub server_id: ServerId,
    pub artifact_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ServerRestoreOutcome {
    pub network_preflight: NetworkPreflight,
    pub events: Vec<InstallEvent>,
    pub profile: ServerProfile,
    pub artifact_sha256: String,
    pub dns_upstream: DnsUpstream,
    pub private_dns_records: Vec<PrivateDnsRecord>,
    pub replaced_existing_installation: bool,
}

#[derive(Debug, Error)]
pub enum InstallerError {
    #[error("the SSH host key is not trusted; verify fingerprint {fingerprint}")]
    HostKeyUnknown { fingerprint: String },
    #[error("the SSH host key does not match the pinned fingerprint")]
    HostKeyMismatch,
    #[error("SSH authentication failed")]
    AuthenticationFailed,
    #[error(
        "SirinVPN is already installed with a different or unavailable owner identity; explicitly replace the SirinVPN installation to rotate ownership"
    )]
    ExistingInstallation,
    #[error("the SSH target is not the Owner installation stored on this device")]
    UninstallTargetMismatch,
    #[error(
        "repair stopped before changing the VPS because its intact SirinVPN identity does not match this Owner profile"
    )]
    RepairTargetMismatch,
    #[error(
        "server backup stopped before reading private VPS state because the installed SirinVPN identity does not match this Owner profile"
    )]
    ServerBackupTargetMismatch,
    #[error(
        "VPS release management stopped because the installed identity does not match this Owner profile"
    )]
    ServerReleaseTargetMismatch,
    #[error(
        "the restore destination already contains SirinVPN state; explicitly confirm replacement or choose a fresh VPS"
    )]
    RestoreTargetOccupied,
    #[error("the encrypted server backup does not match this Owner profile and device identity")]
    RestoreBackupMismatch,
    #[error("the server is incompatible: {0}")]
    Incompatible(String),
    #[error("server transaction failed during {phase}: {message}")]
    PhaseFailed {
        phase: &'static str,
        message: String,
    },
    #[error("invalid installation input: {0}")]
    InvalidInput(String),
    #[error(transparent)]
    ServerBackup(#[from] ServerBackupError),
}

pub struct Provisioner;

impl Provisioner {
    /// Inspect current VPS networking without installing or changing services.
    pub fn inspect_server(
        target: &SshTarget,
        transport: &TransportSetup,
        discovery_port: Option<u16>,
    ) -> Result<NetworkPreflight, InstallerError> {
        transport.validate()?;
        if discovery_port == Some(0) {
            return Err(InstallerError::InvalidInput(
                "The discovery port must be nonzero.".into(),
            ));
        }
        let session =
            connect_transport(target).map_err(|error| phase_error("connection", error))?;
        verify_host_key(&session, target.expected_host_key_sha256.as_deref())?;
        authenticate(&session, target)?;
        let discovery = discover(&session)?;
        check_compatibility(&discovery)?;
        preflight::inspect_network(&session, target, &discovery, transport, discovery_port)
    }
    pub fn host_key_fingerprint(target: &SshTarget) -> Result<String, InstallerError> {
        let session =
            connect_transport(target).map_err(|error| phase_error("connection", error))?;
        fingerprint(&session).map_err(|error| phase_error("host key", error))
    }

    /// Verify a login before storing it locally. Checks the host pin before
    /// sending credentials; this does not execute remote commands or change VPS state.
    pub fn verify_ssh_login(target: &SshTarget) -> Result<(), InstallerError> {
        let session =
            connect_transport(target).map_err(|error| phase_error("connection", error))?;
        verify_host_key(&session, target.expected_host_key_sha256.as_deref())?;
        authenticate(&session, target)
    }

    pub fn install(request: InstallRequest) -> Result<InstallOutcome, InstallerError> {
        validate_request(&request)?;
        let mut events = vec![event(InstallPhase::Connecting, "Contacting the VPS.")];
        let session =
            connect_transport(&request.target).map_err(|error| phase_error("connection", error))?;

        events.push(event(
            InstallPhase::VerifyingHostKey,
            "Verifying the pinned SSH host identity.",
        ));
        verify_host_key(&session, request.target.expected_host_key_sha256.as_deref())?;
        events.push(event(
            InstallPhase::Authenticating,
            "Authenticating directly with the VPS.",
        ));
        authenticate(&session, &request.target)?;
        events.push(event(
            InstallPhase::Discovering,
            "Inspecting the operating system and current network path.",
        ));
        let discovery = discover(&session)?;
        events.push(event(
            InstallPhase::CheckingCompatibility,
            "Checking Debian, architecture, SSH, and network compatibility.",
        ));
        check_compatibility(&discovery)?;
        ensure_dns_upstream_compatible(&request.dns_upstream, discovery.ipv6_available)?;
        if discovery.sirinvpn_installed
            && !request.replace_existing_installation
            && !existing_owner_matches(&session, &request)?
        {
            return Err(InstallerError::ExistingInstallation);
        }

        let owner_client_tunnel_address = FIRST_CLIENT_TUNNEL_ADDRESS.parse().map_err(|_| {
            InstallerError::InvalidInput("invalid built-in client address".to_owned())
        })?;
        stage_and_install(
            &session,
            &request,
            &discovery,
            &mut events,
            InstallTransaction {
                expected_profile: None,
                restore_snapshot: None,
                endpoint_discovery_port: None,
                owner_client_tunnel_address,
                ipv6_tunnel_enabled: discovery.ipv6_available,
            },
        )
    }

    pub fn repair(request: RepairRequest) -> Result<RepairOutcome, InstallerError> {
        validate_repair_request(&request)?;
        let mut events = vec![event(InstallPhase::Connecting, "Contacting the VPS.")];
        let session =
            connect_transport(&request.target).map_err(|error| phase_error("connection", error))?;

        events.push(event(
            InstallPhase::VerifyingHostKey,
            "Verifying the pinned SSH host identity.",
        ));
        verify_host_key(&session, request.target.expected_host_key_sha256.as_deref())?;
        events.push(event(
            InstallPhase::Authenticating,
            "Authenticating directly with the VPS.",
        ));
        authenticate(&session, &request.target)?;
        events.push(event(
            InstallPhase::Discovering,
            "Inspecting the installed SirinVPN state and current network path.",
        ));
        let discovery = discover(&session)?;
        events.push(event(
            InstallPhase::CheckingCompatibility,
            "Checking server identity, state compatibility, and repair boundaries.",
        ));
        check_compatibility(&discovery)?;
        let existing = verify_repair_target(
            &session,
            &request.target,
            &request.profile,
            &request.identity,
            OwnerPreflightOperation::Repair,
        )?;
        ensure_repair_ipv6_compatible(existing.ipv6_tunnel_enabled, discovery.ipv6_available)?;
        let dns_upstream = request
            .dns_upstream
            .clone()
            .unwrap_or(existing.dns_upstream);
        let private_dns_records = request
            .private_dns_records
            .clone()
            .unwrap_or(existing.private_dns_records);
        ensure_dns_upstream_compatible(&dns_upstream, discovery.ipv6_available)?;
        validate_private_dns_records(&private_dns_records)
            .map_err(|error| InstallerError::InvalidInput(error.to_string()))?;

        let install_request = InstallRequest {
            server_id: request.profile.id,
            server_name: request.profile.name.clone(),
            target: request.target.clone(),
            server_binary: request.server_binary.clone(),
            identity: request.identity.clone(),
            identity_reference: request.profile.identity_reference.clone(),
            transport: request
                .transport
                .clone()
                .unwrap_or_else(|| TransportSetup::from_profile(&request.profile)),
            dns_upstream,
            private_dns_records,
            replace_existing_installation: false,
        };
        let outcome = stage_and_install(
            &session,
            &install_request,
            &discovery,
            &mut events,
            InstallTransaction {
                expected_profile: Some(&request.profile),
                restore_snapshot: None,
                endpoint_discovery_port: request
                    .profile
                    .endpoint_discovery_port
                    .or_else(|| request.profile.tls_like.as_ref().map(|tls| tls.port)),
                owner_client_tunnel_address: request.profile.client_tunnel_address,
                ipv6_tunnel_enabled: discovery.ipv6_available,
            },
        )?;
        Ok(RepairOutcome {
            network_preflight: outcome.network_preflight,
            endpoint: outcome.profile.endpoint.clone(),
            endpoint_generation: outcome.profile.endpoint_generation,
            alternate_endpoint_hosts: outcome.profile.alternate_endpoint_hosts,
            endpoint_discovery_port: outcome.profile.endpoint_discovery_port,
            wireguard_port: outcome.profile.endpoint.wireguard_port,
            events: outcome.events,
            artifact_sha256: outcome.artifact_sha256,
            ipv6_tunnel_enabled: outcome.profile.ipv6_tunnel_enabled,
            obfuscated_udp: outcome.profile.obfuscated_udp,
            tcp_fallback: outcome.profile.tcp_fallback,
            tls_like: outcome.profile.tls_like,
            dns_upstream: outcome.dns_upstream,
            private_dns_records: outcome.private_dns_records,
        })
    }

    pub fn export_server_backup(
        request: ServerBackupRequest,
    ) -> Result<ServerBackupOutcome, InstallerError> {
        validate_server_backup_request(&request)?;
        let session =
            connect_transport(&request.target).map_err(|error| phase_error("connection", error))?;
        verify_host_key(&session, request.target.expected_host_key_sha256.as_deref())?;
        authenticate(&session, &request.target)?;
        let discovery = discover(&session)?;
        check_compatibility(&discovery)?;
        if !discovery.sirinvpn_installed {
            return Err(InstallerError::Incompatible(
                "SirinVPN is not installed on the selected VPS".to_owned(),
            ));
        }
        verify_repair_target(
            &session,
            &request.target,
            &request.profile,
            &request.identity,
            OwnerPreflightOperation::ServerBackup,
        )?;

        let (artifact, artifact_sha256) =
            load_install_server_artifact(&request.server_binary, &discovery)?;
        let nonce = Uuid::new_v4().simple().to_string();
        let remote_directory = format!("/tmp/sirinvpn-server-backup-{nonce}");
        run(
            &session,
            &format!(
                "umask 077; install -d -m 0700 {}",
                shell_quote(&remote_directory)
            ),
        )
        .map_err(|error| phase_error("server backup staging", error))?;

        let result = export_server_backup_staged(
            &session,
            &request,
            &remote_directory,
            &artifact,
            &artifact_sha256,
        );
        let _ = run(
            &session,
            &format!(
                "find {} -type f -exec shred -u -- {{}} + 2>/dev/null || true; rmdir {} 2>/dev/null || true",
                shell_quote(&remote_directory),
                shell_quote(&remote_directory)
            ),
        );
        result
    }

    pub fn restore_server_backup(
        request: ServerRestoreRequest,
    ) -> Result<ServerRestoreOutcome, InstallerError> {
        validate_server_restore_request(&request)?;
        let backup = read_encrypted_server_backup(&request.source, request.password.as_str())?;
        if !server_backup_matches_profile(backup.metadata(), &request.profile) {
            return Err(InstallerError::RestoreBackupMismatch);
        }

        let mut events = vec![event(
            InstallPhase::Connecting,
            "Contacting the restore VPS.",
        )];
        let session =
            connect_transport(&request.target).map_err(|error| phase_error("connection", error))?;
        events.push(event(
            InstallPhase::VerifyingHostKey,
            "Verifying the pinned restore VPS SSH identity.",
        ));
        verify_host_key(&session, request.target.expected_host_key_sha256.as_deref())?;
        events.push(event(
            InstallPhase::Authenticating,
            "Authenticating directly with the restore VPS.",
        ));
        authenticate(&session, &request.target)?;
        events.push(event(
            InstallPhase::Discovering,
            "Inspecting the restore VPS and its current SirinVPN-owned state.",
        ));
        let discovery = discover(&session)?;
        events.push(event(
            InstallPhase::CheckingCompatibility,
            "Checking backup, Debian, architecture, network, and replacement boundaries.",
        ));
        check_compatibility(&discovery)?;
        ensure_restore_ipv6_compatible(
            backup.metadata().ipv6_tunnel_enabled,
            discovery.ipv6_available,
        )?;
        ensure_dns_upstream_compatible(&backup.metadata().dns_upstream, discovery.ipv6_available)?;
        let target_occupied = restore_target_has_sirinvpn_state(&session, &request.target)?;
        if target_occupied && !request.replace_existing_installation {
            return Err(InstallerError::RestoreTargetOccupied);
        }

        let install_request = InstallRequest {
            server_id: request.profile.id,
            server_name: request.profile.name.clone(),
            target: request.target.clone(),
            server_binary: request.server_binary.clone(),
            identity: request.identity.clone(),
            identity_reference: request.profile.identity_reference.clone(),
            transport: TransportSetup {
                public_host: Some(request.target.host.clone()),
                ..TransportSetup::from_profile(&request.profile)
            },
            dns_upstream: backup.metadata().dns_upstream.clone(),
            private_dns_records: backup.metadata().private_dns_records.clone(),
            replace_existing_installation: request.replace_existing_installation,
        };
        let outcome = stage_and_install(
            &session,
            &install_request,
            &discovery,
            &mut events,
            InstallTransaction {
                expected_profile: None,
                restore_snapshot: Some(backup.snapshot()),
                endpoint_discovery_port: backup
                    .metadata()
                    .endpoint_discovery_port
                    .or_else(|| backup.metadata().tls_like.as_ref().map(|tls| tls.port)),
                owner_client_tunnel_address: request.profile.client_tunnel_address,
                ipv6_tunnel_enabled: backup.metadata().ipv6_tunnel_enabled,
            },
        )?;
        let mut profile = restored_local_profile(&request.profile, &outcome.profile);
        profile.endpoint_generation = profile
            .endpoint_generation
            .max(backup.metadata().endpoint_generation);
        Ok(ServerRestoreOutcome {
            network_preflight: outcome.network_preflight,
            events: outcome.events,
            profile,
            artifact_sha256: outcome.artifact_sha256,
            dns_upstream: outcome.dns_upstream,
            private_dns_records: outcome.private_dns_records,
            replaced_existing_installation: target_occupied,
        })
    }

    pub fn uninstall(request: UninstallRequest) -> Result<(), InstallerError> {
        validate_uninstall_request(&request)?;
        let session =
            connect_transport(&request.target).map_err(|error| phase_error("connection", error))?;
        verify_host_key(&session, request.target.expected_host_key_sha256.as_deref())?;
        authenticate(&session, &request.target)?;
        verify_uninstall_identity(&session, &request)?;

        let nonce = Uuid::new_v4().simple().to_string();
        let remote_script = format!("/tmp/sirinvpn-uninstall-{nonce}.sh");
        let script = uninstall_script(&nonce);
        upload(
            &session,
            Path::new(&remote_script),
            script.as_bytes(),
            0o700,
        )
        .map_err(|error| phase_error("uninstall staging", error))?;

        session.set_timeout(INSTALL_OPERATION_TIMEOUT_MS);
        let uninstall_result = run_privileged(
            &session,
            &request.target,
            &format!("/bin/sh {}", shell_quote(&remote_script)),
        );
        session.set_timeout(SSH_OPERATION_TIMEOUT_MS);
        if let Err(error) = uninstall_result {
            uninstall_rollback_now(&session, &request.target, &nonce);
            remove_remote_file(&session, &remote_script);
            return Err(phase_error("uninstall", error));
        }

        let verification =
            run_privileged(&session, &request.target, &uninstall_verification_command());
        if let Err(error) = verification {
            uninstall_rollback_now(&session, &request.target, &nonce);
            remove_remote_file(&session, &remote_script);
            return Err(phase_error("uninstall verification", error));
        }

        let commit = run_privileged(&session, &request.target, &uninstall_commit_command(&nonce));
        remove_remote_file(&session, &remote_script);
        commit
            .map(|_| ())
            .map_err(|error| phase_error("uninstall commit", error))
    }
}

pub fn new_identity_for_server(server_name: &str) -> anyhow::Result<LocalIdentity> {
    LocalIdentity::generate(&format!("SirinVPN owner for {server_name}"))
}

pub fn default_install_request(
    server_name: String,
    target: SshTarget,
    server_binary: PathBuf,
    identity: &LocalIdentity,
) -> InstallRequest {
    let id = ServerId::new();
    InstallRequest {
        server_id: id,
        server_name,
        target,
        server_binary: server_binary.into(),
        identity: identity.public.clone(),
        identity_reference: id.to_string(),
        transport: TransportSetup::default(),
        dns_upstream: DnsUpstream::Recursive,
        private_dns_records: Vec::new(),
        replace_existing_installation: false,
    }
}

pub fn management_url() -> String {
    format!("https://{SERVER_TUNNEL_ADDRESS}:{DEFAULT_MANAGEMENT_PORT}")
}

#[cfg(test)]
mod tests;
