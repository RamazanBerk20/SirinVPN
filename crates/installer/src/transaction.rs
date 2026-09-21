//! Transaction.

use super::*;

pub(super) fn restored_local_profile(
    current: &ServerProfile,
    restored: &ServerProfile,
) -> ServerProfile {
    let mut profile = current.clone();
    let previous_transports = profile.endpoint_descriptor();
    let previous_endpoint = profile.endpoint.clone();
    profile.set_endpoint_descriptor(&restored.endpoint_descriptor());
    profile.endpoint_generation = restored
        .endpoint_generation
        .max(current.endpoint_generation);
    if profile.endpoint != previous_endpoint && restored.endpoint_generation == 0 {
        profile.pending_previous_endpoint = Some(previous_endpoint);
        profile.pending_previous_transports = Some(previous_transports);
    } else {
        profile.pending_previous_endpoint = None;
        profile.pending_previous_transports = None;
    }
    profile.server_tunnel_address = restored.server_tunnel_address;
    profile.server_wireguard_public_key = restored.server_wireguard_public_key.clone();
    profile.pinned_server_certificate_pem = restored.pinned_server_certificate_pem.clone();
    profile.ipv6_tunnel_enabled = restored.ipv6_tunnel_enabled;
    profile.obfuscated_udp = restored.obfuscated_udp.clone();
    profile.tcp_fallback = restored.tcp_fallback.clone();
    profile.tls_like = restored.tls_like.clone();
    profile
}

pub(super) fn export_server_backup_staged(
    session: &Session,
    request: &ServerBackupRequest,
    remote_directory: &str,
    artifact: &[u8],
    artifact_sha256: &str,
) -> Result<ServerBackupOutcome, InstallerError> {
    let remote_binary = format!("{remote_directory}/sirinvpn-server");
    let remote_owner = format!("{remote_directory}/owner.crt");
    upload(session, Path::new(&remote_binary), artifact, 0o700)
        .map_err(|error| phase_error("server backup artifact upload", error))?;
    upload(
        session,
        Path::new(&remote_owner),
        request.identity.management_certificate_pem.as_bytes(),
        0o600,
    )
    .map_err(|error| phase_error("server backup owner upload", error))?;

    let remote_digest = run(
        session,
        &format!("sha256sum {} | cut -d' ' -f1", shell_quote(&remote_binary)),
    )
    .map_err(|error| phase_error("server backup artifact verification", error))?;
    if remote_digest.trim() != artifact_sha256 {
        return Err(phase_error(
            "server backup artifact verification",
            anyhow!("uploaded artifact digest mismatch"),
        ));
    }

    let snapshot = run_privileged_bytes(
        session,
        &request.target,
        &server_backup_snapshot_command(&remote_binary, request.profile.id, &remote_owner),
        MAX_SERVER_BACKUP_SNAPSHOT_SIZE,
    )
    .map_err(|error| phase_error("server backup snapshot", error))?;
    write_encrypted_server_backup(
        &request.destination,
        snapshot.as_slice(),
        request.password.as_str(),
    )?;
    Ok(ServerBackupOutcome {
        server_id: request.profile.id,
        artifact_sha256: artifact_sha256.to_owned(),
    })
}

pub(super) fn server_backup_snapshot_command(
    remote_binary: &str,
    server_id: ServerId,
    remote_owner: &str,
) -> String {
    format!(
        "{} --state-directory /etc/sirinvpn backup-state --server-id {} --owner-certificate {}",
        shell_quote(remote_binary),
        shell_quote(&server_id.to_string()),
        shell_quote(remote_owner),
    )
}

pub(super) fn load_server_artifact(
    server_binary: &Path,
    discovery: &ServerDiscovery,
) -> Result<(Vec<u8>, String), InstallerError> {
    let mut artifact = Vec::new();
    fs::File::open(server_binary)
        .and_then(|file| file.take(MAX_ARTIFACT_SIZE + 1).read_to_end(&mut artifact))
        .map_err(|error| phase_error("artifact", anyhow!(error)))?;
    if artifact.is_empty() || artifact.len() as u64 > MAX_ARTIFACT_SIZE {
        return Err(InstallerError::InvalidInput(
            "server artifact is empty or exceeds 64 MiB".to_owned(),
        ));
    }
    let artifact_architecture = elf_architecture(&artifact).ok_or_else(|| {
        InstallerError::InvalidInput(
            "the server artifact is not a supported 64-bit Linux executable".to_owned(),
        )
    })?;
    if artifact_architecture != discovery.architecture {
        return Err(InstallerError::Incompatible(format!(
            "the server artifact targets {artifact_architecture}, but the VPS is {}",
            discovery.architecture
        )));
    }
    let digest = hex::encode(Sha256::digest(&artifact));
    Ok((artifact, digest))
}

pub(super) fn load_install_server_artifact(
    server_binary: &ServerBinarySource,
    discovery: &ServerDiscovery,
) -> Result<(Vec<u8>, String), InstallerError> {
    if let ServerBinarySource::Signed(bundle) = server_binary {
        return bundle.bytes_for(&discovery.architecture);
    }
    load_server_artifact(
        server_binary.path_for_architecture(&discovery.architecture)?,
        discovery,
    )
}

#[derive(Clone, Copy)]
pub(super) struct InstallTransaction<'a> {
    pub(super) endpoint_discovery_port: Option<u16>,
    pub(super) expected_profile: Option<&'a ServerProfile>,
    pub(super) restore_snapshot: Option<&'a [u8]>,
    pub(super) owner_client_tunnel_address: IpAddr,
    pub(super) ipv6_tunnel_enabled: bool,
}

pub(super) fn stage_and_install(
    session: &Session,
    request: &InstallRequest,
    discovery: &ServerDiscovery,
    events: &mut Vec<InstallEvent>,
    transaction: InstallTransaction<'_>,
) -> Result<InstallOutcome, InstallerError> {
    events.push(event(
        InstallPhase::Staging,
        "Staging verified SirinVPN artifacts with restrictive permissions.",
    ));
    let nonce = Uuid::new_v4().simple().to_string();
    let remote_directory = format!("/tmp/sirinvpn-install-{nonce}");
    run(
        session,
        &format!(
            "umask 077; install -d -m 0700 {}",
            shell_quote(&remote_directory)
        ),
    )
    .map_err(|error| phase_error("staging", error))?;

    let result = install_staged(
        session,
        request,
        discovery,
        &remote_directory,
        &nonce,
        events,
        transaction,
    );
    let _ = run(
        session,
        &format!(
            "find {} -type f -exec shred -u -- {{}} + 2>/dev/null || true; rmdir {} 2>/dev/null || true",
            shell_quote(&remote_directory),
            shell_quote(&remote_directory)
        ),
    );
    result
}

pub(super) fn install_staged(
    session: &Session,
    request: &InstallRequest,
    discovery: &ServerDiscovery,
    remote_directory: &str,
    nonce: &str,
    events: &mut Vec<InstallEvent>,
    transaction: InstallTransaction<'_>,
) -> Result<InstallOutcome, InstallerError> {
    let network = preflight::inspect_network(
        session,
        &request.target,
        discovery,
        &request.transport,
        transaction.endpoint_discovery_port,
    )?;
    network.require_compatible()?;
    for issue in &network.issues {
        events.push(event(InstallPhase::CheckingCompatibility, &issue.message));
    }
    let artifact = release_guard::prepare(session, request, discovery)?;
    let local_digest = artifact.sha256.clone();
    if artifact.preserves_signed_release {
        events.push(event(
            InstallPhase::Staging,
            "Preserving the exact committed signed server release while repairing configuration.",
        ));
    }
    let remote_binary = format!("{remote_directory}/sirinvpn-server");
    let remote_owner = format!("{remote_directory}/owner.crt");
    let remote_script = format!("{remote_directory}/install.sh");
    upload(session, Path::new(&remote_binary), &artifact.bytes, 0o700)
        .map_err(|error| phase_error("artifact upload", error))?;
    upload(
        session,
        Path::new(&remote_owner),
        request.identity.management_certificate_pem.as_bytes(),
        0o600,
    )
    .map_err(|error| phase_error("owner identity upload", error))?;

    let remote_digest = run(
        session,
        &format!("sha256sum {} | cut -d' ' -f1", shell_quote(&remote_binary)),
    )
    .map_err(|error| phase_error("artifact verification", error))?;
    if remote_digest.trim() != local_digest {
        return Err(phase_error(
            "artifact verification",
            anyhow!("uploaded artifact digest mismatch"),
        ));
    }
    let script = install_script(
        request,
        discovery,
        &remote_binary,
        &remote_owner,
        nonce,
        transaction,
        &artifact,
    );
    upload(session, Path::new(&remote_script), script.as_bytes(), 0o700)
        .map_err(|error| phase_error("installer upload", error))?;
    events.push(event(
        InstallPhase::InstallingDependencies,
        "Installing only the required Debian packages.",
    ));
    session.set_timeout(INSTALL_OPERATION_TIMEOUT_MS);
    let installation_command = format!("/bin/sh {}", shell_quote(&remote_script));
    let installation_result = match transaction.restore_snapshot {
        Some(snapshot) => {
            run_privileged_with_input(session, &request.target, &installation_command, snapshot)
        }
        None => run_privileged(session, &request.target, &installation_command),
    };
    session.set_timeout(SSH_OPERATION_TIMEOUT_MS);
    if let Err(error) = installation_result {
        rollback_now(session, &request.target, nonce);
        return Err(phase_error("server configuration", error));
    }

    events.push(event(
        InstallPhase::ConfiguringIdentity,
        if transaction.expected_profile.is_some() {
            "Confirming the current Owner without rotating identity."
        } else if transaction.restore_snapshot.is_some() {
            "Restoring the validated server identity and current authorization."
        } else {
            "Enrolling this device as the local owner."
        },
    ));
    let dns_init_arguments =
        server_dns_init_arguments(&request.dns_upstream, &request.private_dns_records);
    let bootstrap_json = match run_privileged(
        session,
        &request.target,
        &maintenance::followup(
            nonce,
            &format!(
                "/usr/local/lib/sirinvpn/sirinvpn-server init --name {} --owner-certificate /etc/sirinvpn/owner.crt --server-id {} --owner-wireguard-public-key {}{}{}{}",
                shell_quote(&request.server_name),
                shell_quote(&request.server_id.to_string()),
                shell_quote(&request.identity.wireguard_public_key),
                request.transport.port_arguments(),
                if transaction.ipv6_tunnel_enabled {
                    " --ipv6-tunnel-enabled true"
                } else {
                    ""
                },
                dns_init_arguments,
            ),
        ),
    ) {
        Ok(output) => output,
        Err(error) => {
            rollback_now(session, &request.target, nonce);
            return Err(phase_error("owner enrollment", error));
        }
    };
    let bootstrap: BootstrapOutput = match serde_json::from_str(bootstrap_json.trim()) {
        Ok(bootstrap) => bootstrap,
        Err(_) => {
            rollback_now(session, &request.target, nonce);
            return Err(phase_error(
                "owner enrollment",
                anyhow!("server returned invalid bootstrap data"),
            ));
        }
    };
    if !bootstrap_matches_transport(&bootstrap, &request.transport) {
        rollback_now(session, &request.target, nonce);
        return Err(phase_error(
            "transport verification",
            anyhow!("server transport metadata did not match the requested configuration"),
        ));
    }
    let valid_checkpoint = bootstrap.endpoint_transition.as_ref().is_some_and(|head| {
        let claims = &head.claims;
        sirinvpn_core::DecodedEndpointTransition::from_response(head.clone()).is_ok()
            && claims.server_id == request.server_id
            && claims.server_wireguard_public_key == bootstrap.wireguard_public_key
            && claims.pinned_server_certificate_pem == bootstrap.management_certificate_pem
            && claims.server_tunnel_address == bootstrap.server_tunnel_address
            && claims.endpoint.host
                == request
                    .transport
                    .public_host
                    .as_deref()
                    .unwrap_or(&request.target.host)
            && claims.endpoint.wireguard_port == bootstrap.wireguard_port
            && claims.alternate_endpoint_hosts == request.transport.alternate_endpoint_hosts
            && claims.endpoint_discovery_port
                == Some(
                    transaction
                        .endpoint_discovery_port
                        .unwrap_or(request.transport.tcp_tls_port),
                )
            && claims.ipv6_tunnel_enabled == bootstrap.ipv6_tunnel_enabled
            && claims.obfuscated_udp == bootstrap.obfuscated_udp
            && claims.tcp_fallback == bootstrap.tcp_fallback
            && claims.tls_like == bootstrap.tls_like
    });
    if !valid_checkpoint {
        rollback_now(session, &request.target, nonce);
        return Err(phase_error(
            "endpoint verification",
            anyhow!("server did not publish the requested signed endpoint checkpoint"),
        ));
    }
    if bootstrap.obfuscated_udp.as_ref().is_none_or(|endpoint| {
        endpoint.port != request.transport.obfuscated_udp_port
            || STANDARD
                .decode(&endpoint.server_public_key)
                .ok()
                .filter(|key| key.len() == 32 && key.iter().any(|byte| *byte != 0))
                .is_none()
    }) {
        rollback_now(session, &request.target, nonce);
        return Err(phase_error(
            "owner enrollment",
            anyhow!("server did not enable the required Obfuscated UDP capability"),
        ));
    }
    if bootstrap.tcp_fallback.as_ref().is_none_or(|endpoint| {
        endpoint.port != request.transport.tcp_tls_port
            || STANDARD
                .decode(&endpoint.server_public_key)
                .ok()
                .filter(|key| key.len() == 32 && key.iter().any(|byte| *byte != 0))
                .is_none()
    }) {
        rollback_now(session, &request.target, nonce);
        return Err(phase_error(
            "owner enrollment",
            anyhow!("server did not enable the required TCP fallback capability"),
        ));
    }
    if bootstrap.tls_like.as_ref().is_none_or(|endpoint| {
        endpoint.port != request.transport.tcp_tls_port
            || STANDARD
                .decode(&endpoint.server_public_key)
                .ok()
                .filter(|key| key.len() == 32 && key.iter().any(|byte| *byte != 0))
                .is_none()
            || STANDARD
                .decode(&endpoint.certificate_sha256)
                .ok()
                .filter(|fingerprint| fingerprint.len() == 32)
                .is_none()
    }) {
        rollback_now(session, &request.target, nonce);
        return Err(phase_error(
            "owner enrollment",
            anyhow!("server did not enable the required TLS-like capability"),
        ));
    }
    if bootstrap.dns_upstream != request.dns_upstream {
        rollback_now(session, &request.target, nonce);
        return Err(phase_error(
            "owner enrollment",
            anyhow!("server did not apply the requested DNS upstream policy"),
        ));
    }
    if bootstrap.private_dns_records != request.private_dns_records {
        rollback_now(session, &request.target, nonce);
        return Err(phase_error(
            "owner enrollment",
            anyhow!("server did not apply the requested private DNS records"),
        ));
    }
    if transaction.expected_profile.is_some_and(|profile| {
        !bootstrap_matches_profile_with_transport(&bootstrap, profile, &request.transport)
    }) {
        rollback_now(session, &request.target, nonce);
        return Err(InstallerError::RepairTargetMismatch);
    }

    events.push(event(
        InstallPhase::ConfiguringNetwork,
        "Applying isolated WireGuard, DNS, routing, and firewall configuration.",
    ));
    events.push(event(
        InstallPhase::VerifyingServices,
        "Checking WireGuard, private DNS, management, and the SSH path.",
    ));
    if let Err(error) = run_privileged(
        session,
        &request.target,
        &maintenance::followup(
            nonce,
            &install_verification_command(&local_digest, &bootstrap, request.server_id, discovery),
        ),
    ) {
        rollback_now(session, &request.target, nonce);
        return Err(phase_error("health verification", error));
    }

    events.push(event(
        InstallPhase::Committing,
        "Committing the verified installation and disarming rollback.",
    ));
    run_privileged(session, &request.target, &maintenance::commit(nonce, false))
        .map_err(|error| phase_error("commit", error))?;
    events.push(event(
        InstallPhase::Complete,
        "The VPS is ready for Direct UDP, Obfuscated UDP, TLS-like, or authenticated TCP fallback.",
    ));

    Ok(InstallOutcome {
        network_preflight: network,
        profile: ServerProfile {
            favorite: false,
            schema_version: 1,
            id: request.server_id,
            name: request.server_name.clone(),
            endpoint: ServerEndpoint {
                host: request
                    .transport
                    .public_host
                    .clone()
                    .unwrap_or_else(|| request.target.host.clone()),
                wireguard_port: bootstrap.wireguard_port,
            },
            endpoint_generation: bootstrap
                .endpoint_transition
                .as_ref()
                .map_or(0, |head| head.claims.generation),
            pending_previous_endpoint: None,
            pending_previous_transports: None,
            endpoint_discovery_port: bootstrap
                .endpoint_transition
                .as_ref()
                .and_then(|head| head.claims.endpoint_discovery_port),
            alternate_endpoint_hosts: request.transport.alternate_endpoint_hosts.clone(),
            client_tunnel_address: transaction.owner_client_tunnel_address,
            server_tunnel_address: bootstrap.server_tunnel_address,
            server_wireguard_public_key: bootstrap.wireguard_public_key,
            pinned_server_certificate_pem: bootstrap.management_certificate_pem,
            client_management_certificate_pem: request.identity.management_certificate_pem.clone(),
            identity_reference: request.identity_reference.clone(),
            role: ServerRole::Owner,
            administrator: false,
            member_id: None,
            device_id: None,
            ipv6_tunnel_enabled: bootstrap.ipv6_tunnel_enabled,
            obfuscated_udp: bootstrap.obfuscated_udp,
            tcp_fallback: bootstrap.tcp_fallback,
            tls_like: bootstrap.tls_like,
        },
        discovery: discovery.clone(),
        events: events.clone(),
        artifact_sha256: local_digest,
        dns_upstream: bootstrap.dns_upstream,
        private_dns_records: bootstrap.private_dns_records,
    })
}

#[derive(Deserialize)]
pub(super) struct BootstrapOutput {
    #[serde(default)]
    pub(super) endpoint_transition: Option<sirinvpn_protocol::EndpointTransitionResponse>,
    pub(super) wireguard_public_key: String,
    pub(super) management_certificate_pem: String,
    pub(super) server_tunnel_address: std::net::IpAddr,
    pub(super) wireguard_port: u16,
    #[allow(dead_code)]
    pub(super) management_port: u16,
    #[serde(default)]
    pub(super) dns_upstream: DnsUpstream,
    #[serde(default)]
    pub(super) private_dns_records: Vec<PrivateDnsRecord>,
    #[serde(default)]
    pub(super) ipv6_tunnel_enabled: bool,
    #[serde(default)]
    pub(super) obfuscated_udp: Option<ObfuscatedUdpEndpoint>,
    #[serde(default)]
    pub(super) tcp_fallback: Option<TcpFallbackEndpoint>,
    #[serde(default)]
    pub(super) tls_like: Option<TlsLikeEndpoint>,
}

pub(super) fn bootstrap_matches_profile_with_transport(
    bootstrap: &BootstrapOutput,
    profile: &ServerProfile,
    transport: &TransportSetup,
) -> bool {
    let mut expected = profile.clone();
    expected.endpoint.wireguard_port = bootstrap.wireguard_port;
    expected.obfuscated_udp = bootstrap.obfuscated_udp.clone();
    expected.tcp_fallback = bootstrap.tcp_fallback.clone();
    expected.tls_like = bootstrap.tls_like.clone();
    let same_key = |old: Option<&str>, new: Option<&str>| old.is_none_or(|key| new == Some(key));
    let certificate_may_change = transport.https_certificate_path.is_some()
        || transport.disable_https
        || profile
            .tls_like
            .as_ref()
            .and_then(|tls| tls.https.as_ref())
            .map(|https| &https.server_name)
            != transport.https.as_ref().map(|https| &https.server_name);
    let pin_matches = certificate_may_change
        || profile.tls_like.as_ref().is_none_or(|old| {
            bootstrap
                .tls_like
                .as_ref()
                .is_some_and(|new| old.certificate_sha256 == new.certificate_sha256)
        });
    pin_matches
        && bootstrap_matches_profile(bootstrap, &expected)
        && bootstrap_matches_transport(bootstrap, transport)
        && same_key(
            profile
                .obfuscated_udp
                .as_ref()
                .map(|e| e.server_public_key.as_str()),
            bootstrap
                .obfuscated_udp
                .as_ref()
                .map(|e| e.server_public_key.as_str()),
        )
        && same_key(
            profile
                .tcp_fallback
                .as_ref()
                .map(|e| e.server_public_key.as_str()),
            bootstrap
                .tcp_fallback
                .as_ref()
                .map(|e| e.server_public_key.as_str()),
        )
        && same_key(
            profile
                .tls_like
                .as_ref()
                .map(|e| e.server_public_key.as_str()),
            bootstrap
                .tls_like
                .as_ref()
                .map(|e| e.server_public_key.as_str()),
        )
}

pub(super) fn bootstrap_matches_profile(
    bootstrap: &BootstrapOutput,
    profile: &ServerProfile,
) -> bool {
    bootstrap.wireguard_public_key == profile.server_wireguard_public_key
        && bootstrap.management_certificate_pem == profile.pinned_server_certificate_pem
        && bootstrap.server_tunnel_address == profile.server_tunnel_address
        && bootstrap.wireguard_port == profile.endpoint.wireguard_port
        && bootstrap.management_port == DEFAULT_MANAGEMENT_PORT
        && profile
            .obfuscated_udp
            .as_ref()
            .is_none_or(|expected| bootstrap.obfuscated_udp.as_ref() == Some(expected))
        && profile
            .tcp_fallback
            .as_ref()
            .is_none_or(|expected| bootstrap.tcp_fallback.as_ref() == Some(expected))
        && profile
            .tls_like
            .as_ref()
            .is_none_or(|expected| bootstrap.tls_like.as_ref() == Some(expected))
}
