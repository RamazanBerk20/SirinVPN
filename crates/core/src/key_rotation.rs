use crate::{
    ClientPaths, LocalIdentity, ManagementClient, ManagementError, ProfileStoreError,
    PublicIdentity, SecretIdentity, SecretStore, SecretStoreError,
    management_certificate_fingerprint,
};
use serde::{Deserialize, Serialize};
use sirinvpn_protocol::{
    DeviceId, KeyRotationId, KeyRotationPrepareRequest, ServerId, ServerProfile, ServerStatus,
    TransportKind,
};
use std::{fs, io, path::PathBuf};
use thiserror::Error;

const KEY_ROTATION_JOURNAL_SCHEMA_VERSION: u16 = 1;
mod policy;
pub use policy::RotationConnectionPolicy;

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
    mut disconnect: Disconnect,
    mut connect: Connect,
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
    let profiles = paths.profile_store();
    let secrets = paths.secret_store();
    let journals = RotationJournalStore::new(paths);
    let mut resumed = true;
    let mut journal = match journals.load(server_id)? {
        Some(journal) => journal,
        None => {
            resumed = false;
            let profile = profiles
                .load()?
                .into_iter()
                .find(|profile| profile.id == server_id)
                .ok_or(ProfileStoreError::NotFound)?;
            let original_secret = secrets.get(&profile.identity_reference)?;
            validate_original_identity(&profile, &original_secret)?;
            let client = ManagementClient::new(&profile, &original_secret)?;
            let configuration = client.configuration().await?;
            if !configuration.key_rotation_enabled {
                return Err(KeyRotationError::UnsupportedServer);
            }
            verify_status_identity(
                &client.status().await?,
                &profile.client_management_certificate_pem,
            )?;
            stage_rotation(
                &journals,
                &secrets,
                profile,
                &original_secret,
                persistent_protection,
                transport,
                transport_fallback_enabled,
                connection_policy,
            )?
        }
    };

    if journal.phase == RotationPhase::Activated {
        let final_secret = secrets.get(&journal.final_identity_reference)?;
        let (status, client) = connect_and_verify(
            &profiles,
            &mut disconnect,
            &mut connect,
            &journal.new_profile(),
            &final_secret,
            &journal.new_public_identity.management_certificate_pem,
            RotationConnectionMode {
                persistent_protection: journal.persistent_protection,
                connection_policy: journal.connection_policy.clone(),
                transport: journal.transport,
                transport_fallback_enabled: journal.transport_fallback_enabled,
            },
        )
        .await?;
        return activate_and_finish(
            &profiles,
            &secrets,
            &journals,
            &mut journal,
            status,
            client,
            resumed,
        )
        .await;
    }

    let original_secret = secrets.get(&journal.original_profile.identity_reference)?;
    let transition_secret = secrets.get(&journal.transition_identity_reference)?;
    let final_secret = secrets.get(&journal.final_identity_reference)?;
    validate_staged_identities(
        &journal,
        &original_secret,
        &transition_secret,
        &final_secret,
    )?;

    if journal.phase == RotationPhase::Committing
        && let Ok((status, client)) = connect_and_verify(
            &profiles,
            &mut disconnect,
            &mut connect,
            &journal.new_profile(),
            &final_secret,
            &journal.new_public_identity.management_certificate_pem,
            RotationConnectionMode {
                persistent_protection: journal.persistent_protection,
                connection_policy: journal.connection_policy.clone(),
                transport: journal.transport,
                transport_fallback_enabled: journal.transport_fallback_enabled,
            },
        )
        .await
    {
        activate_and_finish(
            &profiles,
            &secrets,
            &journals,
            &mut journal,
            status,
            client,
            resumed,
        )
        .await
    } else {
        let old_client = if resumed {
            match connect_and_verify(
                &profiles,
                &mut disconnect,
                &mut connect,
                &journal.original_profile,
                &original_secret,
                &journal.original_profile.client_management_certificate_pem,
                RotationConnectionMode {
                    persistent_protection: journal.persistent_protection,
                    connection_policy: journal.connection_policy.clone(),
                    transport: journal.transport,
                    transport_fallback_enabled: journal.transport_fallback_enabled,
                },
            )
            .await
            {
                Ok((_, client)) => client,
                Err(_) => {
                    profiles.upsert(journal.original_profile.clone())?;
                    return Err(KeyRotationError::RecoveryRequired(
                            "neither the old nor new device identity could be confirmed; restore network access and run key rotation again"
                                .to_owned(),
                    ));
                }
            }
        } else {
            ManagementClient::new(&journal.original_profile, &original_secret)?
        };

        if !old_client.configuration().await?.key_rotation_enabled {
            return Err(KeyRotationError::RecoveryRequired(
                "the VPS no longer exposes the safe rotation protocol; repair/update the server, reconnect the old identity, and resume"
                    .to_owned(),
            ));
        }

        if matches!(
            journal.phase,
            RotationPhase::Staged | RotationPhase::Prepared
        ) {
            let request = KeyRotationPrepareRequest {
                rotation_id: journal.rotation_id,
                server_id,
                new_wireguard_public_key: journal.new_public_identity.wireguard_public_key.clone(),
                new_management_certificate_pem: journal
                    .new_public_identity
                    .management_certificate_pem
                    .clone(),
            };
            match old_client.prepare_key_rotation(&request).await {
                Ok(response) if response.rotation_id == journal.rotation_id => {
                    journal.phase = RotationPhase::Prepared;
                    journals.update(&journal)?;
                }
                Ok(_) => return Err(KeyRotationError::InvalidState),
                Err(ManagementError::ConnectionFailed) => {
                    return Err(KeyRotationError::RecoveryRequired(
                        "preparation may have reached the VPS; keep the local journal and run key rotation again"
                            .to_owned(),
                    ));
                }
                Err(error) => {
                    abandon_staged_rotation(&secrets, &journals, &journal)?;
                    return Err(error.into());
                }
            }
        }

        journal.phase = RotationPhase::Committing;
        journals.update(&journal)?;
        let mut transition_profile = journal.original_profile.clone();
        transition_profile.client_management_certificate_pem = journal
            .new_public_identity
            .management_certificate_pem
            .clone();
        transition_profile.identity_reference = journal.transition_identity_reference.clone();
        let transition_client = ManagementClient::new(&transition_profile, &transition_secret)?;
        let commit_result = transition_client
            .commit_key_rotation(journal.rotation_id)
            .await;
        let expected_new_fingerprint = management_certificate_fingerprint(
            &journal.new_public_identity.management_certificate_pem,
        )
        .map_err(|_| KeyRotationError::InvalidState)?;
        if let Ok(response) = &commit_result
            && (response.server_id != server_id
                || response.identity_fingerprint != expected_new_fingerprint)
        {
            return Err(KeyRotationError::InvalidState);
        }

        match connect_and_verify(
            &profiles,
            &mut disconnect,
            &mut connect,
            &journal.new_profile(),
            &final_secret,
            &journal.new_public_identity.management_certificate_pem,
            RotationConnectionMode {
                persistent_protection: journal.persistent_protection,
                connection_policy: journal.connection_policy.clone(),
                transport: journal.transport,
                transport_fallback_enabled: journal.transport_fallback_enabled,
            },
        )
        .await
        {
            Ok((status, client)) => {
                activate_and_finish(
                    &profiles,
                    &secrets,
                    &journals,
                    &mut journal,
                    status,
                    client,
                    resumed,
                )
                .await
            }
            Err(_) => {
                match connect_and_verify(
                    &profiles,
                    &mut disconnect,
                    &mut connect,
                    &journal.original_profile,
                    &original_secret,
                    &journal.original_profile.client_management_certificate_pem,
                    RotationConnectionMode {
                        persistent_protection: journal.persistent_protection,
                        connection_policy: journal.connection_policy.clone(),
                        transport: journal.transport,
                        transport_fallback_enabled: journal.transport_fallback_enabled,
                    },
                )
                .await
                {
                    Ok((status, client)) => {
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
                        profiles.upsert(journal.original_profile.clone())?;
                        journals.update(&journal)?;
                        Err(KeyRotationError::RecoveryRequired(
                            "the VPS kept the old identity, which was restored locally; run key rotation again to retry the commit"
                                .to_owned(),
                        ))
                    }
                    Err(_) => {
                        profiles.upsert(journal.original_profile.clone())?;
                        Err(KeyRotationError::RecoveryRequired(
                            "the commit result is uncertain and neither identity can currently reach the VPS; restore network access and run key rotation again"
                                .to_owned(),
                        ))
                    }
                }
            }
        }
    }
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
) -> Result<RotationJournal, KeyRotationError> {
    let rotation_id = KeyRotationId::new();
    let transition_identity_reference = format!("rotation-{rotation_id}-transition");
    let final_identity_reference = format!("rotation-{rotation_id}-final");
    ensure_unused_secret_reference(secrets, &transition_identity_reference)?;
    ensure_unused_secret_reference(secrets, &final_identity_reference)?;
    let generated = LocalIdentity::generate("SirinVPN rotated device")
        .map_err(|_| KeyRotationError::InvalidState)?;
    if generated.public.wireguard_public_key
        == original_secret
            .public_identity(&profile.client_management_certificate_pem)
            .map_err(|_| KeyRotationError::InvalidState)?
            .wireguard_public_key
        || generated.public.management_certificate_pem == profile.client_management_certificate_pem
    {
        return Err(KeyRotationError::InvalidState);
    }
    let transition_secret = SecretIdentity {
        wireguard_private_key: original_secret.wireguard_private_key.clone(),
        management_private_key_pem: generated.secret.management_private_key_pem.clone(),
    };
    secrets.put(&transition_identity_reference, &transition_secret)?;
    if let Err(error) = secrets.put(&final_identity_reference, &generated.secret) {
        let _ = secrets.delete(&transition_identity_reference);
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
        let _ = secrets.delete(&journal.transition_identity_reference);
        let _ = secrets.delete(&journal.final_identity_reference);
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
        || final_public != journal.new_public_identity
        || final_public.wireguard_public_key == original_public.wireguard_public_key
    {
        return Err(KeyRotationError::InvalidState);
    }
    Ok(())
}

async fn connect_and_verify<Disconnect, Connect>(
    profiles: &crate::ProfileStore,
    disconnect: &mut Disconnect,
    connect: &mut Connect,
    profile: &ServerProfile,
    secret: &SecretIdentity,
    expected_certificate: &str,
    mode: RotationConnectionMode,
) -> Result<(ServerStatus, ManagementClient), KeyRotationError>
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
    disconnect().map_err(KeyRotationError::Tunnel)?;
    profiles.upsert(profile.clone())?;
    connect(
        profile,
        secret,
        mode.persistent_protection,
        mode.transport,
        mode.transport_fallback_enabled,
        mode.connection_policy.as_ref(),
    )
    .map_err(KeyRotationError::Tunnel)?;
    let client = ManagementClient::new(profile, secret)?;
    let status = client.status().await?;
    verify_status_identity(&status, expected_certificate)?;
    Ok((status, client))
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

async fn activate_and_finish(
    profiles: &crate::ProfileStore,
    secrets: &dyn SecretStore,
    journals: &RotationJournalStore,
    journal: &mut RotationJournal,
    status: ServerStatus,
    client: ManagementClient,
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
    profile.role = role;
    profile.administrator = status.caller_administrator;
    journal.original_profile.role = role;
    journal.original_profile.administrator = status.caller_administrator;
    profiles.upsert(profile.clone())?;
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
    profiles.upsert(journal.new_profile())?;
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
    match secrets.get(reference) {
        Err(SecretStoreError::NotFound) => Ok(()),
        Ok(_) => Err(KeyRotationError::InvalidState),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests;
