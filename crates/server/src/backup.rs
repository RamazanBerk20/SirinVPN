//! Backup.

use super::*;

pub fn export_backup_state(
    paths: &ServerPaths,
    expected_server_id: ServerId,
    expected_owner_certificate_pem: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    validate_state(paths)?;
    let configuration = load_configuration(paths)?;
    let configuration_json = read_backup_state_text(
        &paths.configuration,
        MAX_BACKUP_STATE_FILE_BYTES,
        "server configuration",
    )?;
    let wireguard_private_key = read_backup_state_text(
        &paths.wireguard_private_key,
        MAX_BACKUP_STATE_FILE_BYTES,
        "server WireGuard private key",
    )?;
    let transport_private_key = if configuration.obfuscated_udp.is_some()
        || configuration.tcp_fallback.is_some()
        || configuration.tls_like.is_some()
    {
        Some(read_backup_state_text(
            &paths.transport_private_key,
            MAX_BACKUP_STATE_FILE_BYTES,
            "server transport private key",
        )?)
    } else {
        None
    };
    let management_certificate_pem = read_backup_state_text(
        &paths.tls_certificate,
        MAX_BACKUP_STATE_FILE_BYTES,
        "server management certificate",
    )?;
    let management_private_key_pem = read_backup_state_text(
        &paths.tls_private_key,
        MAX_BACKUP_STATE_FILE_BYTES,
        "server management private key",
    )?;
    let authorization_required = authorization_is_required(paths)?;
    let authorization_json = match fs::symlink_metadata(&paths.authorization) {
        Ok(_) => {
            let encoded = Zeroizing::new(read_backup_state_text(
                &paths.authorization,
                MAX_BACKUP_AUTHORIZATION_BYTES,
                "server authorization state",
            )?);
            let mut authorization: AuthorizationDocument =
                serde_json::from_str(encoded.as_str())
                    .context("server authorization state is invalid")?;
            authorization.validate()?;
            if let Some(transition) = &authorization.endpoint_transition {
                verify_endpoint_transition_signature(&paths.tls_private_key, transition)?;
            }
            if authorization.server_id != expected_server_id
                || !authorization_has_owner_certificate(
                    &authorization,
                    expected_owner_certificate_pem,
                )
            {
                bail!("server authorization does not match the requesting owner");
            }
            authorization.prune_expired(unix_time());
            Some(serde_json::to_string_pretty(&authorization)?)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && !authorization_required => {
            if configuration.owner_certificate_pem != expected_owner_certificate_pem {
                bail!("legacy server configuration does not match the requesting owner");
            }
            None
        }
        Err(error) => return Err(error.into()),
    };
    validate_state(paths)?;

    let https_private_key_pem = if configuration.https_certificate_pem.is_some() {
        Some(String::from_utf8(
            read_https_file(&paths.https_private_key)?.to_vec(),
        )?)
    } else {
        None
    };
    let snapshot = ServerBackupState {
        schema_version: if https_private_key_pem.is_some() {
            2
        } else {
            SERVER_BACKUP_STATE_SCHEMA_VERSION
        },
        https_private_key_pem,
        server_id: expected_server_id,
        configuration_json,
        wireguard_private_key,
        transport_private_key,
        management_certificate_pem,
        management_private_key_pem,
        authorization_json,
        authorization_required,
    };
    Ok(Zeroizing::new(serde_json::to_vec(&snapshot)?))
}

pub fn restore_backup_state(
    paths: &ServerPaths,
    expected_server_id: ServerId,
    expected_owner_certificate_pem: &str,
    snapshot: &[u8],
) -> Result<()> {
    if snapshot.is_empty() || snapshot.len() > MAX_SERVER_BACKUP_SNAPSHOT_BYTES {
        bail!("server backup snapshot has an unsafe size");
    }
    let state: ServerBackupState =
        serde_json::from_slice(snapshot).context("server backup snapshot is invalid")?;
    if !matches!(state.schema_version, 1 | 2)
        || (state.schema_version == 2) != state.https_private_key_pem.is_some()
        || state
            .https_private_key_pem
            .as_ref()
            .is_some_and(|pem| pem.is_empty() || pem.len() > 65_536)
        || state.server_id != expected_server_id
        || state.configuration_json.is_empty()
        || state.configuration_json.len() as u64 > MAX_BACKUP_STATE_FILE_BYTES
        || state.wireguard_private_key.is_empty()
        || state.wireguard_private_key.len() as u64 > MAX_BACKUP_STATE_FILE_BYTES
        || state.management_certificate_pem.is_empty()
        || state.management_certificate_pem.len() as u64 > MAX_BACKUP_STATE_FILE_BYTES
        || state.management_private_key_pem.is_empty()
        || state.management_private_key_pem.len() as u64 > MAX_BACKUP_STATE_FILE_BYTES
        || state.transport_private_key.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() as u64 > MAX_BACKUP_STATE_FILE_BYTES
        })
        || state.authorization_json.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() as u64 > MAX_BACKUP_AUTHORIZATION_BYTES
        })
        || (state.authorization_required && state.authorization_json.is_none())
    {
        bail!("server backup snapshot is incompatible");
    }

    let configuration: ServerConfiguration = serde_json::from_str(&state.configuration_json)
        .context("server backup configuration is invalid")?;
    validate_configuration(&configuration)?;
    let authorization = match &state.authorization_json {
        Some(encoded) => {
            let document: AuthorizationDocument =
                serde_json::from_str(encoded).context("server backup authorization is invalid")?;
            document.validate()?;
            if let Some(transition) = &document.endpoint_transition {
                verify_endpoint_transition_signature_with_key(
                    &state.management_private_key_pem,
                    transition,
                )?;
            }
            if document.server_id != expected_server_id
                || !authorization_has_owner_certificate(&document, expected_owner_certificate_pem)
            {
                bail!("server backup does not belong to the requesting owner");
            }
            Some(document)
        }
        None => {
            if state.authorization_required
                || configuration.owner_certificate_pem != expected_owner_certificate_pem
            {
                bail!("legacy server backup does not belong to the requesting owner");
            }
            None
        }
    };
    let transport_required = configuration.obfuscated_udp.is_some()
        || configuration.tcp_fallback.is_some()
        || configuration.tls_like.is_some();
    if transport_required != state.transport_private_key.is_some() {
        bail!("server backup transport identity is inconsistent");
    }
    validate_wireguard_private_key_binding(&configuration, state.wireguard_private_key.as_bytes())?;
    if let Some(transport_private_key) = &state.transport_private_key {
        validate_transport_private_key_binding(&configuration, transport_private_key.as_bytes())?;
    }
    if configuration.https_certificate_pem.is_some() != state.https_private_key_pem.is_some() {
        bail!("backup HTTPS certificate and key are inconsistent");
    }
    if let (Some(certificate), Some(key)) = (
        &configuration.https_certificate_pem,
        &state.https_private_key_pem,
    ) {
        let endpoint = configuration
            .tls_like
            .as_ref()
            .ok_or_else(|| anyhow!("backup HTTPS endpoint is missing"))?;
        let https = endpoint
            .https
            .as_ref()
            .ok_or_else(|| anyhow!("backup HTTPS metadata is missing"))?;
        let (_, fingerprint) =
            custom_certificate_configuration(certificate.as_bytes(), key.as_bytes(), https)?;
        anyhow::ensure!(
            fingerprint == endpoint.certificate_sha256,
            "backup HTTPS certificate pin is inconsistent"
        );
    }
    let client_certificates = authorization.as_ref().map_or_else(
        || vec![configuration.owner_certificate_pem.clone()],
        |document| document.client_certificates(unix_time()),
    );
    tls_configuration_from_material(
        state.management_certificate_pem.as_bytes(),
        state.management_private_key_pem.as_bytes(),
        &client_certificates,
    )?;

    ensure_restore_destination_is_empty(paths)?;
    write_private(&paths.configuration, state.configuration_json.as_bytes())?;
    write_private(
        &paths.wireguard_private_key,
        state.wireguard_private_key.as_bytes(),
    )?;
    if let Some(transport_private_key) = &state.transport_private_key {
        write_private(
            &paths.transport_private_key,
            transport_private_key.as_bytes(),
        )?;
    }
    if let Some(key) = &state.https_private_key_pem {
        write_private(&paths.https_private_key, key.as_bytes())?;
    }
    write_private(
        &paths.tls_certificate,
        state.management_certificate_pem.as_bytes(),
    )?;
    write_private(
        &paths.tls_private_key,
        state.management_private_key_pem.as_bytes(),
    )?;
    if let Some(authorization_json) = &state.authorization_json {
        let authorization_directory = paths
            .authorization
            .parent()
            .context("authorization state path has no parent directory")?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o750)
            .create(authorization_directory)?;
        fs::set_permissions(authorization_directory, fs::Permissions::from_mode(0o750))?;
        write_private(&paths.authorization, authorization_json.as_bytes())?;
    }
    if state.authorization_required {
        write_private(&paths.authorization_required, b"authorization-schema=1\n")?;
    }
    validate_state(paths)
}

pub(super) fn ensure_restore_destination_is_empty(paths: &ServerPaths) -> Result<()> {
    let state_metadata = fs::symlink_metadata(&paths.state_directory)
        .context("server restore state directory is unavailable")?;
    if !state_metadata.file_type().is_dir() {
        bail!("server restore state directory is unsafe");
    }
    let authorization_directory = paths
        .authorization
        .parent()
        .context("authorization state path has no parent directory")?;
    match fs::symlink_metadata(authorization_directory) {
        Ok(_) => bail!("server restore destination already contains authorization state"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    for path in [
        &paths.configuration,
        &paths.wireguard_private_key,
        &paths.transport_private_key,
        &paths.https_private_key,
        &paths.tls_certificate,
        &paths.tls_private_key,
        &paths.authorization_required,
    ] {
        for candidate in [path.to_path_buf(), path.with_extension("new")] {
            match fs::symlink_metadata(&candidate) {
                Ok(_) => bail!("server restore destination already contains private state"),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

pub(super) fn read_backup_state_text(path: &Path, max_bytes: u64, label: &str) -> Result<String> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("{label} is unavailable"))?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > max_bytes
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!("{label} has unsafe type, size, or permissions");
    }
    let bytes = Zeroizing::new(fs::read(path).with_context(|| format!("{label} is unavailable"))?);
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        bail!("{label} has unsafe size");
    }
    String::from_utf8(bytes.to_vec()).with_context(|| format!("{label} is not valid UTF-8"))
}

pub(super) fn authorization_has_owner_certificate(
    authorization: &AuthorizationDocument,
    expected_certificate_pem: &str,
) -> bool {
    let Some(owner_id) = authorization
        .members
        .iter()
        .find(|member| member.role == ServerRole::Owner)
        .map(|member| member.id)
    else {
        return false;
    };
    authorization.devices.iter().any(|device| {
        device.member_id == owner_id
            && device.management_certificate_pem == expected_certificate_pem
    })
}

pub(super) fn authorization_is_required(paths: &ServerPaths) -> Result<bool> {
    match fs::symlink_metadata(&paths.authorization_required) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => bail!("server authorization requirement marker is invalid"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let temporary = path.with_extension("new");
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("could not stage {}", path.display()))?;
    io::Write::write_all(&mut file, contents)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    Ok(())
}

pub(super) fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_private(path, &bytes)
}

#[derive(Clone)]
pub(super) struct AppState {
    pub(super) recovery: Arc<Mutex<authorization_transaction::RecoveryState>>,
    pub(super) measurement_ready: bool,
    pub(super) configuration: ServerConfiguration,
    pub(super) operational_configuration: Option<OperationalConfiguration>,
    pub(super) paths: ServerPaths,
    pub(super) authorization: Option<Arc<RwLock<AuthorizationDocument>>>,
    pub(super) redemption_failures: Arc<Mutex<HashMap<InvitationId, VecDeque<u64>>>>,
    pub(super) live_metrics: Arc<Mutex<LiveMetricSampler>>,
    pub(super) transport_peers: AuthorizedPeers,
    pub(super) transport_activity: ActiveTransportRegistry,
}
