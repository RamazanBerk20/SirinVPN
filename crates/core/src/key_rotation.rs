use crate::{
    ClientPaths, LocalIdentity, ManagementError, ProfileStoreError, PublicIdentity, SecretIdentity,
    SecretStore, SecretStoreError, ServerOperationError, ServerOperationLock,
    generate_preshared_key, management_certificate_fingerprint,
};
use serde::{Deserialize, Serialize};
use sirinvpn_protocol::{
    CurrentConfiguration, DeviceId, KeyRotationId, KeyRotationPrepareRequest, ServerId,
    ServerProfile, ServerStatus, TransportKind,
};
use std::{fs, io, path::PathBuf};
use thiserror::Error;

const KEY_ROTATION_JOURNAL_SCHEMA_VERSION: u16 = 1;
mod policy;
mod remote;
mod steps;
pub use policy::RotationConnectionPolicy;
use remote::{LiveRemote, RotationClient, RotationRemote};
use steps::{Observation, Progress, Step};

#[derive(Debug, Error)]
pub enum KeyRotationError {
    #[error("local server profile operation failed: {0}")]
    Profile(#[from] ProfileStoreError),
    #[error("local device secret operation failed: {0}")]
    Secret(#[from] SecretStoreError),
    #[error("private management operation failed: {0}")]
    Management(#[from] ManagementError),
    #[error("key rotation state is invalid")]
    InvalidState,
    #[error("the server does not support safe device key rotation; repair/update it first")]
    UnsupportedServer,
    #[error("local tunnel operation failed: {0}")]
    Tunnel(String),
    #[error("key rotation needs recovery: {0}")]
    RecoveryRequired(String),
    #[error("key rotation journal operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Operation(#[from] ServerOperationError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct KeyRotationResult {
    pub rotation_id: KeyRotationId,
    pub server_id: ServerId,
    pub device_id: DeviceId,
    pub identity_fingerprint: String,
    pub resumed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RotationPhase {
    Staged,
    Prepared,
    Committing,
    Activated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RotationJournal {
    schema_version: u16,
    rotation_id: KeyRotationId,
    original_profile: ServerProfile,
    new_public_identity: PublicIdentity,
    transition_identity_reference: String,
    final_identity_reference: String,
    persistent_protection: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    connection_policy: Option<RotationConnectionPolicy>,
    #[serde(default, skip_serializing_if = "is_false")]
    transport_fallback_enabled: bool,
    #[serde(default, skip_serializing_if = "TransportKind::is_direct_udp")]
    transport: TransportKind,
    phase: RotationPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    activated_device_id: Option<DeviceId>,
}

impl RotationJournal {
    fn validate(&self, expected_server_id: ServerId) -> Result<(), KeyRotationError> {
        if self
            .connection_policy
            .as_ref()
            .is_some_and(|policy| policy.selected_applications && policy.selected_routes.is_some())
        {
            return Err(KeyRotationError::InvalidState);
        }
        if let Some(mtu) = self
            .connection_policy
            .as_ref()
            .and_then(|policy| policy.mtu_policy)
        {
            mtu.validate(self.original_profile.ipv6_tunnel_enabled)
                .map_err(|_| KeyRotationError::InvalidState)?;
        }
        if self.schema_version
            != if self
                .connection_policy
                .as_ref()
                .is_some_and(|policy| policy.selected_applications)
            {
                4
            } else if self
                .connection_policy
                .as_ref()
                .is_some_and(|policy| policy.mtu_policy.is_some())
            {
                3
            } else if self.connection_policy.is_some() {
                2
            } else {
                KEY_ROTATION_JOURNAL_SCHEMA_VERSION
            }
            || self.original_profile.schema_version != 1
            || self.original_profile.id != expected_server_id
            || self.transition_identity_reference.is_empty()
            || self.final_identity_reference.is_empty()
            || self.transition_identity_reference == self.final_identity_reference
            || self.original_profile.identity_reference == self.transition_identity_reference
            || self.original_profile.identity_reference == self.final_identity_reference
            || (self.transport_fallback_enabled
                && !self.persistent_protection
                && self.connection_policy.is_none())
            || (self.phase == RotationPhase::Activated) != self.activated_device_id.is_some()
            || management_certificate_fingerprint(
                &self.new_public_identity.management_certificate_pem,
            )
            .is_err()
        {
            return Err(KeyRotationError::InvalidState);
        }
        Ok(())
    }

    fn connection_mode(&self) -> RotationConnectionMode {
        RotationConnectionMode {
            persistent_protection: self.persistent_protection,
            connection_policy: self.connection_policy.clone(),
            transport: self.transport,
            transport_fallback_enabled: self.transport_fallback_enabled,
        }
    }

    fn new_profile(&self) -> ServerProfile {
        let mut profile = self.original_profile.clone();
        profile.client_management_certificate_pem =
            self.new_public_identity.management_certificate_pem.clone();
        profile.identity_reference = self.final_identity_reference.clone();
        if let Some(device_id) = self.activated_device_id {
            profile.device_id = Some(device_id);
        }
        profile
    }
}

struct RotationJournalStore {
    directory: PathBuf,
}

impl RotationJournalStore {
    fn new(paths: &ClientPaths) -> Self {
        Self {
            directory: paths.key_rotations_directory.clone(),
        }
    }

    fn path(&self, server_id: ServerId) -> PathBuf {
        self.directory.join(format!("{server_id}.json"))
    }

    fn exists(&self, server_id: ServerId) -> Result<bool, KeyRotationError> {
        match fs::symlink_metadata(self.path(server_id)) {
            Ok(metadata) if metadata.file_type().is_file() => Ok(true),
            Ok(_) => Err(KeyRotationError::InvalidState),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn load(&self, server_id: ServerId) -> Result<Option<RotationJournal>, KeyRotationError> {
        if !self.exists(server_id)? {
            return Ok(None);
        }
        let bytes = fs::read(self.path(server_id))?;
        let journal: RotationJournal =
            serde_json::from_slice(&bytes).map_err(|_| KeyRotationError::InvalidState)?;
        journal.validate(server_id)?;
        Ok(Some(journal))
    }

    fn create(&self, journal: &RotationJournal) -> Result<(), KeyRotationError> {
        self.write(journal, false)
    }

    fn update(&self, journal: &RotationJournal) -> Result<(), KeyRotationError> {
        self.write(journal, true)
    }

    fn write(&self, journal: &RotationJournal, replace: bool) -> Result<(), KeyRotationError> {
        journal.validate(journal.original_profile.id)?;
        sirinvpn_platform::files::create_private_directory(&self.directory)?;
        let bytes =
            serde_json::to_vec_pretty(journal).map_err(|_| KeyRotationError::InvalidState)?;
        let path = self.path(journal.original_profile.id);
        sirinvpn_platform::files::atomic_write(&path, &bytes, replace)?;
        Ok(())
    }

    fn remove(&self, server_id: ServerId) -> Result<(), KeyRotationError> {
        match fs::remove_file(self.path(server_id)) {
            Ok(()) => {
                sirinvpn_platform::files::sync_directory(&self.directory)?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

pub fn has_pending_key_rotation(
    paths: &ClientPaths,
    server_id: ServerId,
) -> Result<bool, KeyRotationError> {
    RotationJournalStore::new(paths).exists(server_id)
}

/// Whether to prompt for a key rotation that gives this device a WireGuard
/// preshared key. Clients only prompt: rotation reconnects, can end in
/// `RecoveryRequired`, and leaves earlier device backups holding retired keys.
pub fn preshared_key_rotation_recommended(
    secret: &SecretIdentity,
    configuration: &CurrentConfiguration,
) -> bool {
    secret.wireguard_preshared_key.is_none()
        && configuration.key_rotation_enabled
        && configuration.preshared_keys_enabled
}

pub async fn rotate_current_device_keys<Disconnect, Connect>(
    paths: &ClientPaths,
    server_id: ServerId,
    persistent_protection: bool,
    transport: TransportKind,
    transport_fallback_enabled: bool,
    mut disconnect: Disconnect,
    mut connect: Connect,
) -> Result<KeyRotationResult, KeyRotationError>
where
    Disconnect: FnMut() -> Result<(), String>,
    Connect:
        FnMut(&ServerProfile, &SecretIdentity, bool, TransportKind, bool) -> Result<(), String>,
{
    rotate_current_device_keys_with_policy(
        paths,
        server_id,
        persistent_protection,
        transport,
        transport_fallback_enabled,
        None,
        &mut disconnect,
        |profile, secret, persistent, transport, fallback, _| {
            connect(profile, secret, persistent, transport, fallback)
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn rotate_current_device_keys_with_policy<Disconnect, Connect>(
    paths: &ClientPaths,
    server_id: ServerId,
    persistent_protection: bool,
    transport: TransportKind,
    transport_fallback_enabled: bool,
    connection_policy: Option<RotationConnectionPolicy>,
    disconnect: Disconnect,
    connect: Connect,
) -> Result<KeyRotationResult, KeyRotationError>
where
    Disconnect: FnMut() -> Result<(), String>,
    Connect: FnMut(
        &ServerProfile,
        &SecretIdentity,
        bool,
        TransportKind,
        bool,
        Option<&RotationConnectionPolicy>,
    ) -> Result<(), String>,
{
    // Held for the whole run: a second CLI, desktop or Android runner, or an endpoint
    // transition, would otherwise reconnect underneath this one.
    let _operation = ServerOperationLock::acquire(paths, server_id)?;
    drive(
        paths,
        &paths.secret_store(),
        &LiveRemote,
        server_id,
        RotationConnectionMode {
            persistent_protection,
            transport,
            transport_fallback_enabled,
            connection_policy,
        },
        disconnect,
        connect,
    )
    .await
}

/// Executes the steps chosen by [`steps::next`]; holds no decisions of its own.
async fn drive<Remote, Disconnect, Connect>(
    paths: &ClientPaths,
    secrets: &dyn SecretStore,
    remote: &Remote,
    server_id: ServerId,
    requested: RotationConnectionMode,
    mut disconnect: Disconnect,
    mut connect: Connect,
) -> Result<KeyRotationResult, KeyRotationError>
where
    Remote: RotationRemote,
    Disconnect: FnMut() -> Result<(), String>,
    Connect: FnMut(
        &ServerProfile,
        &SecretIdentity,
        bool,
        TransportKind,
        bool,
        Option<&RotationConnectionPolicy>,
    ) -> Result<(), String>,
{
    let profiles = paths.profile_store();
    let journals = RotationJournalStore::new(paths);
    let (mut journal, resumed) = match journals.load(server_id)? {
        Some(journal) => (journal, true),
        None => (
            stage_from_current_profile(&profiles, &journals, secrets, remote, server_id, requested)
                .await?,
            false,
        ),
    };
    let final_secret = secrets.get(&journal.final_identity_reference)?;
    // An activated journal may already have deleted the original and transition secrets.
    let staged = if journal.phase == RotationPhase::Activated {
        None
    } else {
        let original = secrets.get(&journal.original_profile.identity_reference)?;
        let transition = secrets.get(&journal.transition_identity_reference)?;
        validate_staged_identities(&journal, &original, &transition, &final_secret)?;
        Some((original, transition))
    };
    let staged_secret = |index: usize| {
        staged
            .as_ref()
            .map(|(original, transition)| if index == 0 { original } else { transition })
            .ok_or(KeyRotationError::InvalidState)
    };
    let mode = journal.connection_mode();

    let mut progress = Progress {
        phase: journal.phase,
        resumed,
        commit_sent: false,
    };
    let mut observation = Observation::Started;
    let mut confirmed_new = None;
    let mut old: Option<(Option<ServerStatus>, Remote::Client)> = None;
    let mut last_error = None;
    loop {
        observation = match steps::next(progress, observation) {
            Step::ConnectNew => {
                match connect_and_verify(
                    &profiles,
                    remote,
                    &mut disconnect,
                    &mut connect,
                    &journal.new_profile(),
                    &final_secret,
                    &mode,
                )
                .await
                {
                    Ok(confirmed) => {
                        confirmed_new = Some(confirmed);
                        Observation::NewIdentityConfirmed
                    }
                    Err(error) => {
                        last_error = Some(error);
                        Observation::NewIdentityUnconfirmed
                    }
                }
            }
            Step::ConnectOld => {
                match connect_and_verify(
                    &profiles,
                    remote,
                    &mut disconnect,
                    &mut connect,
                    &journal.original_profile,
                    staged_secret(0)?,
                    &mode,
                )
                .await
                {
                    Ok((status, client)) => {
                        old = Some((Some(status), client));
                        Observation::OldIdentityConfirmed
                    }
                    Err(_) => Observation::OldIdentityUnconfirmed,
                }
            }
            Step::UseOld => {
                old = Some((
                    None,
                    remote.client(&journal.original_profile, staged_secret(0)?)?,
                ));
                Observation::OldIdentityConfirmed
            }
            Step::CheckSupport => {
                let (_, client) = old.as_ref().ok_or(KeyRotationError::InvalidState)?;
                if client.capabilities().await?.key_rotation {
                    Observation::RotationSupported
                } else {
                    Observation::RotationUnsupported
                }
            }
            Step::Prepare => {
                let (_, client) = old.as_ref().ok_or(KeyRotationError::InvalidState)?;
                let request = KeyRotationPrepareRequest {
                    rotation_id: journal.rotation_id,
                    server_id,
                    new_wireguard_public_key: journal
                        .new_public_identity
                        .wireguard_public_key
                        .clone(),
                    new_management_certificate_pem: journal
                        .new_public_identity
                        .management_certificate_pem
                        .clone(),
                    new_wireguard_preshared_key: final_secret.wireguard_preshared_key.clone(),
                };
                match client.prepare(&request).await {
                    Ok(response) if response.rotation_id == journal.rotation_id => {
                        journal.phase = RotationPhase::Prepared;
                        journals.update(&journal)?;
                        Observation::Prepared
                    }
                    Ok(_) => return Err(KeyRotationError::InvalidState),
                    Err(ManagementError::ConnectionFailed) => Observation::PrepareUncertain,
                    Err(error) => {
                        last_error = Some(error.into());
                        Observation::PrepareRejected
                    }
                }
            }
            Step::Commit => {
                journal.phase = RotationPhase::Committing;
                journals.update(&journal)?;
                let mut transition_profile = journal.original_profile.clone();
                transition_profile.client_management_certificate_pem = journal
                    .new_public_identity
                    .management_certificate_pem
                    .clone();
                transition_profile.identity_reference =
                    journal.transition_identity_reference.clone();
                let commit_result = remote
                    .client(&transition_profile, staged_secret(1)?)?
                    .commit(journal.rotation_id)
                    .await;
                let expected_new_fingerprint = management_certificate_fingerprint(
                    &journal.new_public_identity.management_certificate_pem,
                )
                .map_err(|_| KeyRotationError::InvalidState)?;
                // A lost response is expected when the old peer goes; only a wrong one is fatal.
                if let Ok(response) = &commit_result
                    && (response.server_id != server_id
                        || response.identity_fingerprint != expected_new_fingerprint)
                {
                    return Err(KeyRotationError::InvalidState);
                }
                progress.commit_sent = true;
                Observation::CommitSent
            }
            Step::Activate => {
                let (status, client) =
                    confirmed_new.take().ok_or(KeyRotationError::InvalidState)?;
                return activate_and_finish(
                    &profiles,
                    secrets,
                    &journals,
                    &mut journal,
                    status,
                    client,
                    resumed,
                )
                .await;
            }
            Step::Abandon => {
                abandon_staged_rotation(secrets, &journals, &journal)?;
                return Err(last_error.unwrap_or(KeyRotationError::InvalidState));
            }
            Step::KeepOld => {
                let (Some(status), client) = old.as_ref().ok_or(KeyRotationError::InvalidState)?
                else {
                    return Err(KeyRotationError::InvalidState);
                };
                if let Some(role) = status.caller_role {
                    journal.original_profile.role = role;
                    journal.original_profile.administrator = status.caller_administrator;
                }
                client
                    .refresh_membership_ids(
                        &mut journal.original_profile,
                        status
                            .caller_device_id
                            .ok_or(KeyRotationError::InvalidState)?,
                    )
                    .await?;
                journal.phase = RotationPhase::Prepared;
                write_device_identity(&profiles, &journal.original_profile)?;
                journals.update(&journal)?;
                return Err(KeyRotationError::RecoveryRequired(
                    "the VPS kept the old identity, which was restored locally; run key rotation again to retry the commit"
                        .to_owned(),
                ));
            }
            Step::Stop => return Err(last_error.unwrap_or(KeyRotationError::InvalidState)),
            Step::Fail(failure) => {
                if failure.restores_original_identity() {
                    // Never point the profile at an identity whose deletion has started.
                    if matches!(
                        secrets.state(&journal.original_profile.identity_reference)?,
                        crate::CredentialState::Deleting | crate::CredentialState::Deleted
                    ) {
                        return Err(KeyRotationError::RecoveryRequired(
                            "the original device identity was already deleted; reconnect and run key rotation again to finish with the new identity".to_owned(),
                        ));
                    }
                    write_device_identity(&profiles, &journal.original_profile)?;
                }
                return Err(failure
                    .message()
                    .map_or(KeyRotationError::InvalidState, |message| {
                        KeyRotationError::RecoveryRequired(message.to_owned())
                    }));
            }
        };
        progress.phase = journal.phase;
    }
}

async fn stage_from_current_profile<Remote: RotationRemote>(
    profiles: &crate::ProfileStore,
    journals: &RotationJournalStore,
    secrets: &dyn SecretStore,
    remote: &Remote,
    server_id: ServerId,
    requested: RotationConnectionMode,
) -> Result<RotationJournal, KeyRotationError> {
    let profile = profiles
        .load()?
        .into_iter()
        .find(|profile| profile.id == server_id)
        .ok_or(ProfileStoreError::NotFound)?;
    let original_secret = secrets.get(&profile.identity_reference)?;
    validate_original_identity(&profile, &original_secret)?;
    let client = remote.client(&profile, &original_secret)?;
    let capabilities = client.capabilities().await?;
    if !capabilities.key_rotation {
        return Err(KeyRotationError::UnsupportedServer);
    }
    verify_status_identity(
        &client.status().await?,
        &profile.client_management_certificate_pem,
    )?;
    stage_rotation(
        journals,
        secrets,
        profile,
        &original_secret,
        requested.persistent_protection,
        requested.transport,
        requested.transport_fallback_enabled,
        requested.connection_policy,
        capabilities.preshared_keys,
    )
}

#[allow(clippy::too_many_arguments)]
fn stage_rotation(
    journals: &RotationJournalStore,
    secrets: &dyn SecretStore,
    profile: ServerProfile,
    original_secret: &SecretIdentity,
    persistent_protection: bool,
    transport: TransportKind,
    transport_fallback_enabled: bool,
    connection_policy: Option<RotationConnectionPolicy>,
    preshared_keys_enabled: bool,
) -> Result<RotationJournal, KeyRotationError> {
    let rotation_id = KeyRotationId::new();
    let transition_identity_reference = format!("rotation-{rotation_id}-transition");
    let final_identity_reference = format!("rotation-{rotation_id}-final");
    ensure_unused_secret_reference(secrets, &transition_identity_reference)?;
    ensure_unused_secret_reference(secrets, &final_identity_reference)?;
    let mut generated = LocalIdentity::generate("SirinVPN rotated device")
        .map_err(|_| KeyRotationError::InvalidState)?;
    // An older VPS would ignore the key and leave the new peer without one.
    if preshared_keys_enabled {
        generated.secret.wireguard_preshared_key = Some(generate_preshared_key());
    }
    if generated.public.wireguard_public_key
        == original_secret
            .public_identity(&profile.client_management_certificate_pem)
            .map_err(|_| KeyRotationError::InvalidState)?
            .wireguard_public_key
        || generated.public.management_certificate_pem == profile.client_management_certificate_pem
    {
        return Err(KeyRotationError::InvalidState);
    }
    // The transition identity still talks through the original peer and its key.
    let transition_secret = SecretIdentity {
        wireguard_private_key: original_secret.wireguard_private_key.clone(),
        management_private_key_pem: generated.secret.management_private_key_pem.clone(),
        wireguard_preshared_key: original_secret.wireguard_preshared_key.clone(),
    };
    secrets.put(&transition_identity_reference, &transition_secret)?;
    if let Err(error) = secrets.put(&final_identity_reference, &generated.secret) {
        if secrets.delete(&transition_identity_reference).is_err() {
            return Err(SecretStoreError::CleanupPending.into());
        }
        return Err(error.into());
    }
    let journal = RotationJournal {
        schema_version: if connection_policy
            .as_ref()
            .is_some_and(|policy| policy.selected_applications)
        {
            4
        } else if connection_policy
            .as_ref()
            .is_some_and(|policy| policy.mtu_policy.is_some())
        {
            3
        } else if connection_policy.is_some() {
            2
        } else {
            KEY_ROTATION_JOURNAL_SCHEMA_VERSION
        },
        connection_policy,
        rotation_id,
        original_profile: profile,
        new_public_identity: generated.public,
        transition_identity_reference,
        final_identity_reference,
        persistent_protection,
        transport_fallback_enabled,
        transport,
        phase: RotationPhase::Staged,
        activated_device_id: None,
    };
    if let Err(error) = journals.create(&journal) {
        let transition = secrets.delete(&journal.transition_identity_reference);
        let final_identity = secrets.delete(&journal.final_identity_reference);
        if transition.is_err() || final_identity.is_err() {
            return Err(SecretStoreError::CleanupPending.into());
        }
        return Err(error);
    }
    Ok(journal)
}

fn validate_original_identity(
    profile: &ServerProfile,
    secret: &SecretIdentity,
) -> Result<(), KeyRotationError> {
    secret
        .public_identity(&profile.client_management_certificate_pem)
        .map_err(|_| KeyRotationError::InvalidState)?;
    Ok(())
}

fn validate_staged_identities(
    journal: &RotationJournal,
    original: &SecretIdentity,
    transition: &SecretIdentity,
    final_identity: &SecretIdentity,
) -> Result<(), KeyRotationError> {
    let original_public = original
        .public_identity(&journal.original_profile.client_management_certificate_pem)
        .map_err(|_| KeyRotationError::InvalidState)?;
    let transition_public = transition
        .public_identity(&journal.new_public_identity.management_certificate_pem)
        .map_err(|_| KeyRotationError::InvalidState)?;
    let final_public = final_identity
        .public_identity(&journal.new_public_identity.management_certificate_pem)
        .map_err(|_| KeyRotationError::InvalidState)?;
    if transition_public.wireguard_public_key != original_public.wireguard_public_key
        || transition.wireguard_preshared_key != original.wireguard_preshared_key
        || final_public != journal.new_public_identity
        || final_public.wireguard_public_key == original_public.wireguard_public_key
        || (final_identity.wireguard_preshared_key.is_some()
            && final_identity.wireguard_preshared_key == original.wireguard_preshared_key)
    {
        return Err(KeyRotationError::InvalidState);
    }
    Ok(())
}

async fn connect_and_verify<Remote, Disconnect, Connect>(
    profiles: &crate::ProfileStore,
    remote: &Remote,
    disconnect: &mut Disconnect,
    connect: &mut Connect,
    identity: &ServerProfile,
    secret: &SecretIdentity,
    mode: &RotationConnectionMode,
) -> Result<(ServerStatus, Remote::Client), KeyRotationError>
where
    Remote: RotationRemote,
    Disconnect: FnMut() -> Result<(), String>,
    Connect: FnMut(
        &ServerProfile,
        &SecretIdentity,
        bool,
        TransportKind,
        bool,
        Option<&RotationConnectionPolicy>,
    ) -> Result<(), String>,
{
    disconnect().map_err(KeyRotationError::Tunnel)?;
    // Connect with the profile as it is now (endpoint, routes, name), carrying the
    // candidate identity; the journal's copy of the rest may be days old.
    let profile = write_device_identity(profiles, identity)?;
    connect(
        &profile,
        secret,
        mode.persistent_protection,
        mode.transport,
        mode.transport_fallback_enabled,
        mode.connection_policy.as_ref(),
    )
    .map_err(KeyRotationError::Tunnel)?;
    let client = remote.client(&profile, secret)?;
    let status = client.status().await?;
    verify_status_identity(&status, &identity.client_management_certificate_pem)?;
    Ok((status, client))
}

/// Rotation owns only the device identity fields of the saved profile. Every other
/// field keeps its current value, including renames and endpoint checkpoints applied
/// while the rotation was staged or interrupted.
fn write_device_identity(
    profiles: &crate::ProfileStore,
    identity: &ServerProfile,
) -> Result<ServerProfile, KeyRotationError> {
    Ok(profiles.update(identity.id, |current| {
        current.identity_reference = identity.identity_reference.clone();
        current.client_management_certificate_pem =
            identity.client_management_certificate_pem.clone();
        current.device_id = identity.device_id;
        current.member_id = identity.member_id;
        current.role = identity.role;
        current.administrator = identity.administrator;
        Ok(current.clone())
    })?)
}

#[derive(Clone)]
struct RotationConnectionMode {
    connection_policy: Option<RotationConnectionPolicy>,
    persistent_protection: bool,
    transport: TransportKind,
    transport_fallback_enabled: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn verify_status_identity(
    status: &ServerStatus,
    expected_certificate: &str,
) -> Result<(), KeyRotationError> {
    let expected = management_certificate_fingerprint(expected_certificate)
        .map_err(|_| KeyRotationError::InvalidState)?;
    if status.caller_device_id.is_none()
        || status.caller_role.is_none()
        || status.caller_identity_fingerprint != expected
    {
        return Err(KeyRotationError::InvalidState);
    }
    Ok(())
}

async fn activate_and_finish<Client: RotationClient>(
    profiles: &crate::ProfileStore,
    secrets: &dyn SecretStore,
    journals: &RotationJournalStore,
    journal: &mut RotationJournal,
    status: ServerStatus,
    client: Client,
    resumed: bool,
) -> Result<KeyRotationResult, KeyRotationError> {
    let device_id = status
        .caller_device_id
        .ok_or(KeyRotationError::InvalidState)?;
    journal.activated_device_id = Some(device_id);
    let mut profile = journal.new_profile();
    client
        .refresh_membership_ids(&mut profile, device_id)
        .await?;
    journal.original_profile.member_id = profile.member_id;
    let role = status.caller_role.ok_or(KeyRotationError::InvalidState)?;
    journal.original_profile.role = role;
    journal.original_profile.administrator = status.caller_administrator;
    write_device_identity(profiles, &journal.new_profile())?;
    journal.phase = RotationPhase::Activated;
    journals.update(journal)?;
    finish_activation(profiles, secrets, journals, journal, resumed)
}

fn finish_activation(
    profiles: &crate::ProfileStore,
    secrets: &dyn SecretStore,
    journals: &RotationJournalStore,
    journal: &RotationJournal,
    resumed: bool,
) -> Result<KeyRotationResult, KeyRotationError> {
    journal.validate(journal.original_profile.id)?;
    let final_secret = secrets.get(&journal.final_identity_reference)?;
    if final_secret
        .public_identity(&journal.new_public_identity.management_certificate_pem)
        .map_err(|_| KeyRotationError::InvalidState)?
        != journal.new_public_identity
    {
        return Err(KeyRotationError::InvalidState);
    }
    write_device_identity(profiles, &journal.new_profile())?;
    secrets.delete(&journal.original_profile.identity_reference)?;
    secrets.delete(&journal.transition_identity_reference)?;
    journals.remove(journal.original_profile.id)?;
    Ok(KeyRotationResult {
        rotation_id: journal.rotation_id,
        server_id: journal.original_profile.id,
        device_id: journal
            .activated_device_id
            .ok_or(KeyRotationError::InvalidState)?,
        identity_fingerprint: management_certificate_fingerprint(
            &journal.new_public_identity.management_certificate_pem,
        )
        .map_err(|_| KeyRotationError::InvalidState)?,
        resumed,
    })
}

fn abandon_staged_rotation(
    secrets: &dyn SecretStore,
    journals: &RotationJournalStore,
    journal: &RotationJournal,
) -> Result<(), KeyRotationError> {
    secrets.delete(&journal.transition_identity_reference)?;
    secrets.delete(&journal.final_identity_reference)?;
    journals.remove(journal.original_profile.id)
}

fn ensure_unused_secret_reference(
    secrets: &dyn SecretStore,
    reference: &str,
) -> Result<(), KeyRotationError> {
    if secrets.new_reference_available(reference)? {
        Ok(())
    } else {
        Err(KeyRotationError::InvalidState)
    }
}

#[cfg(test)]
mod driver_tests;
#[cfg(test)]
mod tests;
