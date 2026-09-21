//! Native optimization survives closing the desktop; private credentials remain
//! root-only and are used exclusively for the pinned, in-tunnel management API.
use super::*;
use sirinvpn_core::{LocalIdentity, ManagementClient, SecretIdentity};
use sirinvpn_protocol::ServerProfile;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedConnectRequest {
    pub expected_server_id: Option<ServerId>,
    pub request: TunnelConnectRequest,
    pub profile: ServerProfile,
    pub secret: SecretIdentity,
}

#[derive(Serialize, Deserialize)]
struct MeasurementIdentity {
    profile: ServerProfile,
    secret: SecretIdentity,
}

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    pub fn connect_managed(
        &self,
        managed: &ManagedConnectRequest,
    ) -> Result<LocalTunnelStatus, HelperError> {
        let request = &managed.request;
        if !identity_matches(request, &managed.profile, &managed.secret) {
            return Err(HelperError::InvalidState);
        }
        let status = if let Some(expected_server_id) = managed.expected_server_id {
            self.switch_session(&SwitchConnectRequest {
                expected_server_id,
                request: request.clone(),
            })?
        } else {
            self.connect(request)?
        };
        let _lock = self.lock_operations()?;
        if self.read_persistent()?.request.server_id != request.server_id
            || self.read_state()?.waiting_for_user
        {
            return Err(HelperError::ActivePolicy);
        }
        let path = self.persistent_directory.join("measurement-identity.json");
        if request.reconnect_candidates.len() > 1 && request.connection_policy().kill_switch {
            let identity = MeasurementIdentity {
                profile: managed.profile.clone(),
                secret: managed.secret.clone(),
            };
            let bytes = Zeroizing::new(
                serde_json::to_vec(&identity).map_err(|_| HelperError::InvalidState)?,
            );
            write_private(&path, &bytes).map_err(|_| HelperError::NetworkOperationFailed)?;
        } else {
            remove_file_if_exists(&path).map_err(|_| HelperError::NetworkOperationFailed)?;
        }
        Ok(status)
    }

    pub(super) fn optimize_session(&self) -> Result<()> {
        let state = self.read_state()?;
        let desired = self.read_persistent()?;
        if !state.has_connected
            || state.reconnecting
            || state.waiting_for_user
            || desired.request.reconnect_candidates.len() < 2
            || !state.connection_policy().kill_switch
            || now_unix().saturating_sub(state.applied_at_unix) < 30
        {
            return Ok(());
        }
        let path = self.runtime_directory.join("measurement-last");
        if fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|at| now_unix() >= at && now_unix() - at < 600)
        {
            return Ok(());
        }
        let identity: MeasurementIdentity = serde_json::from_slice(&Zeroizing::new(fs::read(
            self.persistent_directory.join("measurement-identity.json"),
        )?))?;
        if !identity_matches(&desired.request, &identity.profile, &identity.secret) {
            return Ok(());
        }
        // Record the attempt before IO: unsupported servers and failed probes
        // cannot produce a tight retry loop or repeated live changes.
        fs::write(path, now_unix().to_string())?;
        let client = ManagementClient::new(&identity.profile, &identity.secret)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let capable = runtime
            .block_on(client.configuration())?
            .isolated_measurement_enabled;
        {
            let _lock = self.lock_operations()?;
            let mut current = self.read_state()?;
            if current.server_id != state.server_id
                || current.applied_at_unix != state.applied_at_unix
            {
                return Ok(());
            }
            current
                .quality
                .get_or_insert_with(Default::default)
                .status
                .isolated_measurement_supported = capable;
            self.write_state(&current)?;
        }
        if !capable {
            return Ok(());
        }
        let probe_identity = LocalIdentity::generate("Temporary transport measurement")?;
        let key = probe_identity.public.wireguard_public_key;
        let lease = runtime.block_on(client.measurement_lease(key.clone()))?;
        let current = self.status()?;
        let probe = MeasureSessionRequest {
            server_id: state.server_id,
            counter_epoch: current.counter_epoch.unwrap_or_default(),
            lease,
            private_key: probe_identity.secret.wireguard_private_key.clone(),
        };
        let result = self.measure_session(&probe);
        let _ = runtime.block_on(client.remove_measurement_lease(key));
        result?;
        Ok(())
    }
}

fn identity_matches(
    request: &TunnelConnectRequest,
    profile: &ServerProfile,
    secret: &SecretIdentity,
) -> bool {
    request.server_id == profile.id
        && request.server_public_key == profile.server_wireguard_public_key
        && IpAddr::V4(request.dns_address) == profile.server_tunnel_address
        && IpAddr::V4(request.client_address) == profile.client_tunnel_address
        && secret.wireguard_private_key == request.private_key
        && secret
            .public_identity(&profile.client_management_certificate_pem)
            .is_ok()
        && ManagementClient::new(profile, secret).is_ok()
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file =
        tempfile::NamedTempFile::new_in(path.parent().ok_or(io::ErrorKind::InvalidInput)?)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    Ok(())
}
