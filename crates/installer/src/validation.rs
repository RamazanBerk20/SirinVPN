//! Validation.

use super::*;

#[derive(Deserialize)]
pub(super) struct ExistingServerIdentity {
    pub(super) schema_version: u16,
    pub(super) owner_certificate_pem: String,
    #[serde(default)]
    pub(super) dns_upstream: DnsUpstream,
    #[serde(default)]
    pub(super) private_dns_records: Vec<PrivateDnsRecord>,
}

#[derive(Deserialize)]
pub(super) struct ExistingAuthorizationIdentity {
    pub(super) schema_version: u16,
    pub(super) server_id: ServerId,
    pub(super) members: Vec<ExistingAuthorizationMember>,
    pub(super) devices: Vec<ExistingAuthorizationDevice>,
}

#[derive(Deserialize)]
pub(super) struct ExistingRepairConfiguration {
    pub(super) schema_version: u16,
    pub(super) interface_name: String,
    pub(super) tunnel_cidr: String,
    pub(super) server_tunnel_address: IpAddr,
    pub(super) wireguard_port: u16,
    pub(super) management_port: u16,
    pub(super) wireguard_public_key: String,
    pub(super) owner_certificate_pem: String,
    #[serde(default)]
    pub(super) ipv6_tunnel_enabled: bool,
    #[serde(default)]
    pub(super) dns_upstream: DnsUpstream,
    #[serde(default)]
    pub(super) private_dns_records: Vec<PrivateDnsRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RepairPreflight {
    pub(super) ipv6_tunnel_enabled: bool,
    pub(super) dns_upstream: DnsUpstream,
    pub(super) private_dns_records: Vec<PrivateDnsRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RepairIdentityCheck {
    Match,
    Incompatible,
    Mismatch,
}

#[derive(Deserialize)]
pub(super) struct ExistingAuthorizationMember {
    pub(super) id: MemberId,
    pub(super) role: ServerRole,
    #[serde(default)]
    pub(super) suspended: bool,
    #[serde(default)]
    pub(super) policy: sirinvpn_protocol::MemberPolicy,
}

#[derive(Deserialize)]
pub(super) struct ExistingAuthorizationDevice {
    pub(super) member_id: MemberId,
    pub(super) wireguard_public_key: String,
    pub(super) management_certificate_pem: String,
}

pub(super) fn existing_owner_matches(
    session: &Session,
    request: &InstallRequest,
) -> Result<bool, InstallerError> {
    let configuration = run_privileged(
        session,
        &request.target,
        "if [ -s /etc/sirinvpn/server.json ]; then cat /etc/sirinvpn/server.json; fi",
    )
    .map_err(|error| phase_error("existing installation inspection", error))?;
    let authorization = run_privileged(
        session,
        &request.target,
        "if [ -s /etc/sirinvpn/authorization/authorization.json ]; then cat /etc/sirinvpn/authorization/authorization.json; fi",
    )
    .map_err(|error| phase_error("existing authorization inspection", error))?;
    if authorization.trim().is_empty() {
        return Ok(configuration_owner_matches(
            &configuration,
            &request.identity.management_certificate_pem,
        ));
    }
    Ok(authorization_owner_matches(
        &authorization,
        request.server_id,
        &request.identity.management_certificate_pem,
        Some(&request.identity.wireguard_public_key),
    ))
}

pub(super) fn configuration_owner_matches(configuration: &str, expected_certificate: &str) -> bool {
    serde_json::from_str::<ExistingServerIdentity>(configuration).is_ok_and(|existing| {
        supported_dns_schema(
            existing.schema_version,
            &existing.dns_upstream,
            &existing.private_dns_records,
        ) && existing.owner_certificate_pem == expected_certificate
    })
}

pub(super) fn supported_dns_schema(
    schema_version: u16,
    dns_upstream: &DnsUpstream,
    private_dns_records: &[PrivateDnsRecord],
) -> bool {
    validate_server_dns_configuration(schema_version, dns_upstream, private_dns_records).is_ok()
}

#[derive(Clone, Copy)]
pub(super) enum OwnerPreflightOperation {
    Repair,
    ServerBackup,
    Release,
}

impl OwnerPreflightOperation {
    pub(super) fn identity_phase(self) -> &'static str {
        match self {
            Self::Repair => "repair identity preflight",
            Self::ServerBackup => "server backup identity preflight",
            Self::Release => "VPS release identity preflight",
        }
    }

    pub(super) fn configuration_phase(self) -> &'static str {
        match self {
            Self::Repair => "repair configuration preflight",
            Self::ServerBackup => "server backup configuration preflight",
            Self::Release => "VPS release configuration preflight",
        }
    }

    pub(super) fn authorization_phase(self) -> &'static str {
        match self {
            Self::Repair => "repair authorization preflight",
            Self::ServerBackup => "server backup authorization preflight",
            Self::Release => "VPS release authorization preflight",
        }
    }

    pub(super) fn certificate_phase(self) -> &'static str {
        match self {
            Self::Repair => "repair certificate preflight",
            Self::ServerBackup => "server backup certificate preflight",
            Self::Release => "VPS release certificate preflight",
        }
    }

    pub(super) fn mismatch(self) -> InstallerError {
        match self {
            Self::Repair => InstallerError::RepairTargetMismatch,
            Self::ServerBackup => InstallerError::ServerBackupTargetMismatch,
            Self::Release => InstallerError::ServerReleaseTargetMismatch,
        }
    }
}

pub(super) fn verify_repair_target(
    session: &Session,
    target: &SshTarget,
    profile: &ServerProfile,
    identity: &PublicIdentity,
    operation: OwnerPreflightOperation,
) -> Result<RepairPreflight, InstallerError> {
    let state_probe = run_privileged(
        session,
        target,
        r#"set -eu
for path in /etc/sirinvpn/server.json /etc/sirinvpn/wireguard.key /etc/sirinvpn/management.crt /etc/sirinvpn/management.key; do
  [ -s "$path" ] || { printf 'missing\n'; exit 0; }
  [ "$(wc -c <"$path")" -le 65536 ] || { printf 'oversized\n'; exit 0; }
done
if [ -e /etc/sirinvpn/authorization-required ] || [ -d /etc/sirinvpn/authorization ]; then
  [ -s /etc/sirinvpn/authorization/authorization.json ] || { printf 'missing\n'; exit 0; }
  [ "$(wc -c </etc/sirinvpn/authorization/authorization.json)" -le 1048576 ] || { printf 'oversized\n'; exit 0; }
fi
printf 'ready\n'"#,
    )
    .map_err(|error| phase_error(operation.identity_phase(), error))?;
    if state_probe.trim() != "ready" {
        return Err(operation.mismatch());
    }
    let configuration = run_privileged(session, target, "cat /etc/sirinvpn/server.json")
        .map_err(|error| phase_error(operation.configuration_phase(), error))?;
    let authorization = run_privileged(
        session,
        target,
        "if [ -s /etc/sirinvpn/authorization/authorization.json ]; then cat /etc/sirinvpn/authorization/authorization.json; fi",
    )
    .map_err(|error| phase_error(operation.authorization_phase(), error))?;
    let server_certificate = run_privileged(session, target, "cat /etc/sirinvpn/management.crt")
        .map_err(|error| phase_error(operation.certificate_phase(), error))?;
    match repair_identity_check(
        &configuration,
        &authorization,
        &server_certificate,
        profile,
        identity,
    ) {
        RepairIdentityCheck::Match => {
            serde_json::from_str::<ExistingRepairConfiguration>(&configuration)
                .map(|configuration| RepairPreflight {
                    ipv6_tunnel_enabled: configuration.ipv6_tunnel_enabled,
                    dns_upstream: configuration.dns_upstream,
                    private_dns_records: configuration.private_dns_records,
                })
                .map_err(|_| operation.mismatch())
        }
        RepairIdentityCheck::Incompatible => Err(InstallerError::Incompatible(
            "the installed SirinVPN state uses an unsupported schema or network layout".to_owned(),
        )),
        RepairIdentityCheck::Mismatch => Err(operation.mismatch()),
    }
}

pub(super) fn repair_identity_check(
    configuration: &str,
    authorization: &str,
    server_certificate: &str,
    profile: &ServerProfile,
    identity: &PublicIdentity,
) -> RepairIdentityCheck {
    let Ok(configuration) = serde_json::from_str::<ExistingRepairConfiguration>(configuration)
    else {
        return RepairIdentityCheck::Mismatch;
    };
    if !supported_dns_schema(
        configuration.schema_version,
        &configuration.dns_upstream,
        &configuration.private_dns_records,
    ) {
        return RepairIdentityCheck::Incompatible;
    }
    let expected_server_address = match SERVER_TUNNEL_ADDRESS.parse::<IpAddr>() {
        Ok(address) => address,
        Err(_) => return RepairIdentityCheck::Incompatible,
    };
    if configuration.interface_name != INTERFACE_NAME
        || configuration.tunnel_cidr != TUNNEL_CIDR
        || configuration.server_tunnel_address != expected_server_address
        || configuration.management_port != DEFAULT_MANAGEMENT_PORT
    {
        return RepairIdentityCheck::Incompatible;
    }
    if configuration.wireguard_port != profile.endpoint.wireguard_port
        || configuration.wireguard_public_key != profile.server_wireguard_public_key
        || server_certificate != profile.pinned_server_certificate_pem
    {
        return RepairIdentityCheck::Mismatch;
    }
    if authorization.trim().is_empty() {
        return if configuration.owner_certificate_pem == identity.management_certificate_pem {
            RepairIdentityCheck::Match
        } else {
            RepairIdentityCheck::Mismatch
        };
    }
    let Ok(document) = serde_json::from_str::<ExistingAuthorizationIdentity>(authorization) else {
        return RepairIdentityCheck::Mismatch;
    };
    if !matches!(document.schema_version, 1..=5) {
        return RepairIdentityCheck::Incompatible;
    }
    if authorization_owner_matches(
        authorization,
        profile.id,
        &identity.management_certificate_pem,
        Some(&identity.wireguard_public_key),
    ) {
        RepairIdentityCheck::Match
    } else {
        RepairIdentityCheck::Mismatch
    }
}

pub(super) fn verify_uninstall_identity(
    session: &Session,
    request: &UninstallRequest,
) -> Result<(), InstallerError> {
    let configuration = run_privileged(
        session,
        &request.target,
        "if [ -s /etc/sirinvpn/server.json ]; then cat /etc/sirinvpn/server.json; fi",
    )
    .map_err(|error| phase_error("uninstall identity inspection", error))?;
    let authorization = run_privileged(
        session,
        &request.target,
        "if [ -s /etc/sirinvpn/authorization/authorization.json ]; then cat /etc/sirinvpn/authorization/authorization.json; fi",
    )
    .map_err(|error| phase_error("uninstall authorization inspection", error))?;
    if !uninstall_identity_matches(
        &configuration,
        &authorization,
        request.server_id,
        &request.owner_certificate_pem,
    ) {
        return Err(InstallerError::UninstallTargetMismatch);
    }
    Ok(())
}

pub(super) fn uninstall_identity_matches(
    configuration: &str,
    authorization: &str,
    expected_server_id: ServerId,
    expected_certificate: &str,
) -> bool {
    serde_json::from_str::<ExistingServerIdentity>(configuration).is_ok_and(|existing| {
        supported_dns_schema(
            existing.schema_version,
            &existing.dns_upstream,
            &existing.private_dns_records,
        )
    }) && authorization_owner_matches(
        authorization,
        expected_server_id,
        expected_certificate,
        None,
    )
}

pub(super) fn authorization_owner_matches(
    authorization: &str,
    expected_server_id: ServerId,
    expected_certificate: &str,
    expected_wireguard_public_key: Option<&str>,
) -> bool {
    let Ok(existing) = serde_json::from_str::<ExistingAuthorizationIdentity>(authorization) else {
        return false;
    };
    if existing.server_id != expected_server_id
        || !matches!(existing.schema_version, 1..=5)
        || (existing.schema_version == 1 && existing.members.iter().any(|member| member.suspended))
        || (existing.schema_version < 3
            && existing
                .members
                .iter()
                .any(|member| !member.policy.is_default()))
        || existing
            .members
            .iter()
            .any(|member| member.policy.validate().is_err())
        || existing
            .members
            .iter()
            .filter(|member| member.role == ServerRole::Owner)
            .count()
            != 1
    {
        return false;
    }
    let Some(owner) = existing
        .members
        .iter()
        .find(|member| member.role == ServerRole::Owner)
    else {
        return false;
    };
    if owner.suspended || !owner.policy.is_default() {
        return false;
    }
    existing.devices.iter().any(|device| {
        device.member_id == owner.id
            && device.management_certificate_pem == expected_certificate
            && expected_wireguard_public_key
                .is_none_or(|expected| device.wireguard_public_key == expected)
    })
}

pub(super) fn validate_request(request: &InstallRequest) -> Result<(), InstallerError> {
    validate_server_name(&request.server_name)
        .map_err(|error| InstallerError::InvalidInput(error.to_string()))?;
    validate_target(&request.target)?;
    request.transport.validate()?;
    if request.transport.wireguard_port == 0 {
        return Err(InstallerError::InvalidInput(
            "WireGuard port must be non-zero".to_owned(),
        ));
    }
    validate_dns_upstream(&request.dns_upstream)
        .map_err(|error| InstallerError::InvalidInput(error.to_string()))?;
    validate_private_dns_records(&request.private_dns_records)
        .map_err(|error| InstallerError::InvalidInput(error.to_string()))?;
    Ok(())
}

pub(super) fn validate_repair_request(request: &RepairRequest) -> Result<(), InstallerError> {
    if let Some(transport) = &request.transport {
        transport.validate()?;
    }
    validate_owner_operation_request(
        &request.profile,
        &request.target,
        &request.identity,
        "repair",
    )?;
    if let Some(dns_upstream) = &request.dns_upstream {
        validate_dns_upstream(dns_upstream)
            .map_err(|error| InstallerError::InvalidInput(error.to_string()))?;
    }
    if let Some(private_dns_records) = &request.private_dns_records {
        validate_private_dns_records(private_dns_records)
            .map_err(|error| InstallerError::InvalidInput(error.to_string()))?;
    }
    Ok(())
}

pub(super) fn validate_server_backup_request(
    request: &ServerBackupRequest,
) -> Result<(), InstallerError> {
    validate_owner_operation_request(
        &request.profile,
        &request.target,
        &request.identity,
        "server backup",
    )?;
    validate_server_backup_password(request.password.as_str())?;
    if request.destination.as_os_str().is_empty() {
        return Err(InstallerError::InvalidInput(
            "the server backup destination is empty".to_owned(),
        ));
    }
    if fs::symlink_metadata(&request.destination).is_ok() {
        return Err(ServerBackupError::DestinationExists.into());
    }
    Ok(())
}

pub(super) fn validate_server_restore_request(
    request: &ServerRestoreRequest,
) -> Result<(), InstallerError> {
    validate_target(&request.target)?;
    validate_owner_profile_identity(&request.profile, &request.identity, "server restore")?;
    if request.profile.pending_previous_endpoint.is_some()
        && request.target.host != request.profile.endpoint.host
    {
        return Err(InstallerError::InvalidInput(
            "publish or clear the pending endpoint update before migrating this server again"
                .to_owned(),
        ));
    }
    if request.source.as_os_str().is_empty() {
        return Err(InstallerError::InvalidInput(
            "the encrypted server backup path is empty".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_owner_operation_request(
    profile: &ServerProfile,
    target: &SshTarget,
    identity: &PublicIdentity,
    operation: &str,
) -> Result<(), InstallerError> {
    validate_target(target)?;
    if profile.endpoint.host != target.host {
        return Err(InstallerError::InvalidInput(format!(
            "the local Owner profile targets a different host for {operation}"
        )));
    }
    validate_owner_profile_identity(profile, identity, operation)
}

pub(super) fn validate_owner_profile_identity(
    profile: &ServerProfile,
    identity: &PublicIdentity,
    operation: &str,
) -> Result<(), InstallerError> {
    validate_server_name(&profile.name)
        .map_err(|error| InstallerError::InvalidInput(error.to_string()))?;
    if profile.schema_version != 1
        || profile.role != ServerRole::Owner
        || profile.endpoint.wireguard_port == 0
        || profile.server_tunnel_address
            != SERVER_TUNNEL_ADDRESS.parse::<IpAddr>().map_err(|_| {
                InstallerError::InvalidInput("invalid built-in server address".into())
            })?
        || profile.client_management_certificate_pem != identity.management_certificate_pem
        || profile.pinned_server_certificate_pem.trim().is_empty()
        || !valid_wireguard_public_key(&profile.server_wireguard_public_key)
        || !valid_wireguard_public_key(&identity.wireguard_public_key)
        || !valid_owner_client_tunnel_address(profile.client_tunnel_address)
    {
        return Err(InstallerError::InvalidInput(format!(
            "the local Owner profile or device identity is invalid for {operation}"
        )));
    }
    Ok(())
}

pub(super) fn valid_owner_client_tunnel_address(address: IpAddr) -> bool {
    matches!(
        address,
        IpAddr::V4(address)
            if address.octets()[..3] == [10, 77, 0] && address.octets()[3] >= 2
    )
}

pub(super) fn server_backup_matches_profile(
    backup: &ServerBackupMetadata,
    profile: &ServerProfile,
) -> bool {
    backup.server_id == profile.id
        && backup.server_tunnel_address == profile.server_tunnel_address
        && backup.wireguard_port == profile.endpoint.wireguard_port
        && backup.server_wireguard_public_key == profile.server_wireguard_public_key
        && backup.management_certificate_pem == profile.pinned_server_certificate_pem
}

pub(super) fn restore_target_has_sirinvpn_state(
    session: &Session,
    target: &SshTarget,
) -> Result<bool, InstallerError> {
    let result = run_privileged(
        session,
        target,
        r#"if [ -e /etc/sirinvpn ] || [ -e /usr/local/lib/sirinvpn/sirinvpn-server ] || [ -e /etc/unbound/unbound.conf.d/sirinvpn.conf ] || [ -e /etc/systemd/system/unbound.service.d/sirinvpn.conf ] || [ -e /etc/systemd/system/sirinvpn-network.service ] || [ -e /etc/systemd/system/sirinvpn-firewall.service ] || [ -e /etc/systemd/system/sirinvpn-doh.service ] || [ -e /etc/systemd/system/sirinvpn-server.service ]; then printf 'present\n'; else printf 'empty\n'; fi"#,
    )
    .map_err(|error| phase_error("restore destination inspection", error))?;
    match result.trim() {
        "present" => Ok(true),
        "empty" => Ok(false),
        _ => Err(phase_error(
            "restore destination inspection",
            anyhow!("restore destination returned an invalid state marker"),
        )),
    }
}

pub(super) fn valid_wireguard_public_key(value: &str) -> bool {
    STANDARD
        .decode(value)
        .is_ok_and(|decoded| decoded.len() == 32 && STANDARD.encode(decoded.as_slice()) == value)
}

pub(super) fn validate_uninstall_request(request: &UninstallRequest) -> Result<(), InstallerError> {
    validate_target(&request.target)?;
    if request.owner_certificate_pem.trim().is_empty() {
        return Err(InstallerError::InvalidInput(
            "the local Owner certificate is unavailable".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_target(target: &SshTarget) -> Result<(), InstallerError> {
    validate_host(&target.host).map_err(|error| InstallerError::InvalidInput(error.to_string()))?;
    if target.port == 0 {
        return Err(InstallerError::InvalidInput(
            "SSH port must be non-zero".to_owned(),
        ));
    }
    if target.username.is_empty()
        || target.username.len() > 64
        || target
            .username
            .chars()
            .any(|character| !character.is_ascii_alphanumeric() && !matches!(character, '_' | '-'))
    {
        return Err(InstallerError::InvalidInput(
            "SSH username contains unsupported characters".to_owned(),
        ));
    }
    match &target.authentication {
        SshAuthentication::Password(password)
            if password.is_empty() || password.len() > 4 * 1024 || password.contains('\0') =>
        {
            return Err(InstallerError::InvalidInput(
                "the SSH password is invalid or exceeds its size limit".to_owned(),
            ));
        }
        SshAuthentication::PrivateKeyMemory {
            private_key_pem,
            passphrase,
        } if private_key_pem.is_empty()
            || private_key_pem.len() > 64 * 1024
            || private_key_pem.contains('\0')
            || passphrase
                .as_ref()
                .is_some_and(|value| value.len() > 4 * 1024 || value.contains('\0')) =>
        {
            return Err(InstallerError::InvalidInput(
                "the in-memory SSH private key is invalid or exceeds its size limit".to_owned(),
            ));
        }
        _ => {}
    }
    if target
        .sudo_password
        .as_ref()
        .is_some_and(|value| value.len() > 4 * 1024 || value.contains('\0'))
    {
        return Err(InstallerError::InvalidInput(
            "the sudo password is invalid or exceeds its size limit".to_owned(),
        ));
    }
    Ok(())
}
