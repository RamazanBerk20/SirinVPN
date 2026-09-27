//! The authorization write lock owns transactions and recovery. Dirty is set before
//! the first await and only cleared after durable authority and every effect agree.
use super::*;
use sirinvpn_protocol::{AuthorizationHealth, AuthorizationRecovery};

#[derive(Default)]
pub(super) struct RecoveryState {
    pub status: AuthorizationRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Stage {
    Contain,
    Quarantine,
    Wireguard,
    Isolation,
    Forwarding,
    Persist,
    Transport,
    Checkpoint,
    Complete,
}

/// Fault seams correspond to actual OS/persistence boundaries; policy stays here.
pub(super) trait Effects: Sync {
    fn intent(
        &self,
        previous: &AuthorizationDocument,
        next: &AuthorizationDocument,
        generation: u64,
    ) -> Result<()>;
    fn authority(&self) -> Result<AuthorizationDocument>;
    fn execute(
        &self,
        stage: Stage,
        document: &AuthorizationDocument,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

fn status(state: &Mutex<RecoveryState>) -> AuthorizationRecovery {
    state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .status
        .clone()
}
fn update(state: &Mutex<RecoveryState>, change: impl FnOnce(&mut AuthorizationRecovery)) {
    change(&mut state.lock().unwrap_or_else(|e| e.into_inner()).status);
}

pub(super) fn needs_recovery(state: &Mutex<RecoveryState>) -> bool {
    status(state).health != AuthorizationHealth::Healthy
}

async fn network(io: &impl Effects, document: &AuthorizationDocument) -> bool {
    let mut complete = true;
    // Containment remains installed. Do not short-circuit restoration after an error.
    for stage in [
        Stage::Quarantine,
        Stage::Wireguard,
        Stage::Isolation,
        Stage::Forwarding,
    ] {
        complete &= io.execute(stage, document).await.is_ok();
    }
    complete
}

async fn publish(io: &impl Effects, document: &AuthorizationDocument) -> bool {
    let transport = io.execute(Stage::Transport, document).await.is_ok();
    let checkpoint = io.execute(Stage::Checkpoint, document).await.is_ok();
    transport && checkpoint
}

pub(super) async fn recover(
    io: &impl Effects,
    state: &Mutex<RecoveryState>,
    current: &mut AuthorizationDocument,
) -> Result<()> {
    let generation = status(state).generation;
    update(state, |s| s.health = AuthorizationHealth::RecoveryPending);
    let contained = io.execute(Stage::Contain, current).await.is_ok();
    update(state, |s| s.containment_verified = contained);
    if !contained {
        update(state, |s| s.health = AuthorizationHealth::RecoveryFailed);
        bail!("authorization containment is unavailable");
    }
    let restored = async {
        // Reload after any interrupted/ambiguous write; never assume memory is authority.
        let authoritative = io.authority()?;
        *current = authoritative;
        // Also retries the durability boundary after an ambiguous post-rename error.
        io.execute(Stage::Persist, current).await?;
        let effects = network(io, current).await;
        let published = publish(io, current).await;
        if !effects || !published {
            bail!("authorization recovery is incomplete");
        }
        update(state, |s| s.containment_verified = false);
        io.execute(Stage::Complete, current).await
    }
    .await;
    update(state, |s| {
        if s.generation == generation {
            s.health = if restored.is_ok() {
                AuthorizationHealth::Healthy
            } else {
                AuthorizationHealth::RecoveryFailed
            };
            if restored.is_ok() {
                s.containment_verified = false;
            }
        }
    });
    restored
}

pub(super) async fn commit(
    io: &impl Effects,
    state: &Mutex<RecoveryState>,
    current: &mut AuthorizationDocument,
    mut next: AuthorizationDocument,
) -> Result<(), ApiError> {
    if needs_recovery(state) {
        return Err(ApiError::conflict(
            "authorization recovery is pending; retry after recovery",
        ));
    }
    next.schema_version = next.required_schema_version();
    next.validate().map_err(|_| ApiError::internal())?;
    decoded_transport_peers(&next).map_err(|_| ApiError::internal())?;
    checkpoint(&next).map_err(|_| ApiError::internal())?;
    update(state, |s| {
        s.generation = s.generation.saturating_add(1);
        s.health = AuthorizationHealth::Applying;
        s.containment_verified = false;
        s.committed = false;
    });
    if io.intent(current, &next, status(state).generation).is_err() {
        update(state, |s| s.health = AuthorizationHealth::RecoveryPending);
        return Err(recovery_error(false));
    }
    if io.execute(Stage::Contain, current).await.is_err() {
        update(state, |s| s.health = AuthorizationHealth::RecoveryFailed);
        return Err(recovery_error(false));
    }
    update(state, |s| s.containment_verified = true);
    if !network(io, &next).await {
        let restored = recover(io, state, current).await.is_ok();
        return Err(if restored {
            ApiError::conflict("authorization change failed; previous policy restored")
        } else {
            recovery_error(false)
        });
    }
    if io.execute(Stage::Persist, &next).await.is_err() {
        // A failed directory fsync can follow replacement. It is unsafe to roll back
        // based only on the error returned by the persistence helper.
        let committed = io
            .authority()
            .is_ok_and(|document| fingerprint(&document).ok() == fingerprint(&next).ok());
        update(state, |s| s.committed = committed);
        let restored = recover(io, state, current).await.is_ok();
        return Err(if committed {
            recovery_error(true)
        } else if restored {
            ApiError::conflict("authorization change failed; previous policy restored")
        } else {
            recovery_error(false)
        });
    }
    *current = next;
    update(state, |s| s.committed = true);
    let published = publish(io, current).await;
    update(state, |s| s.containment_verified = false);
    if !published || io.execute(Stage::Complete, current).await.is_err() {
        update(state, |s| s.health = AuthorizationHealth::RecoveryPending);
        return Err(recovery_error(true));
    }
    update(state, |s| {
        s.health = AuthorizationHealth::Healthy;
        s.containment_verified = false;
    });
    Ok(())
}

fn recovery_error(committed: bool) -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::ConflictDetected,
        if committed {
            "authorization was committed; enforcement/publication must be checked before retrying"
        } else {
            "authorization change failed; enforcement recovery is pending"
        },
    )
}

pub(super) fn fingerprint(document: &AuthorizationDocument) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(document)?)))
}

fn checkpoint(document: &AuthorizationDocument) -> Result<Option<Vec<u8>>> {
    let bytes = document
        .endpoint_transition
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()?;
    if bytes
        .as_ref()
        .is_some_and(|b| b.is_empty() || b.len() > 24 * 1024)
    {
        bail!("invalid checkpoint size");
    }
    Ok(bytes)
}

pub(super) struct Host<'a>(pub &'a AppState);
impl Effects for Host<'_> {
    fn intent(
        &self,
        previous: &AuthorizationDocument,
        next: &AuthorizationDocument,
        generation: u64,
    ) -> Result<()> {
        journal::write(&self.0.paths, previous, next, generation)
    }
    fn authority(&self) -> Result<AuthorizationDocument> {
        journal::validate(&self.0.paths)?;
        load_authorization(&self.0.paths.authorization)
    }
    async fn execute(&self, stage: Stage, document: &AuthorizationDocument) -> Result<()> {
        let state = self.0;
        match stage {
            Stage::Contain => {
                apply_nft_batch(
                    &containment(&state.configuration, true),
                    "authorization containment",
                )
                .await
            }
            Stage::Quarantine => {
                apply_nft_batch(
                    &enrollment_quarantine_nft_batch(&state.configuration, document.server_id),
                    "enrollment quarantine",
                )
                .await
            }
            Stage::Wireguard => sync_wireguard_peers(&state.configuration, document).await,
            Stage::Isolation => sync_peer_isolation(&state.configuration, document).await,
            Stage::Forwarding => {
                sync_port_forwards(
                    &state.configuration,
                    state.operational_configuration.as_ref(),
                    document,
                )
                .await
            }
            Stage::Persist => write_authorization(&state.paths.authorization, document),
            Stage::Transport => {
                state
                    .transport_peers
                    .replace(decoded_transport_peers(document)?);
                Ok(())
            }
            Stage::Checkpoint => Ok(state
                .transport_peers
                .publish_endpoint_checkpoint(checkpoint(document)?)?),
            Stage::Complete => {
                journal::remove(&state.paths)?;
                apply_nft_batch(
                    &containment(&state.configuration, false),
                    "authorization containment release",
                )
                .await
            }
        }
    }
}

/// Uses the existing owned handoff table, so installer cleanup/rollback already owns it.
/// Separate chains survive ordinary peer-isolation/handoff refreshes.
pub(super) fn containment(configuration: &ServerConfiguration, enabled: bool) -> String {
    let mut batch = concat!(
        "add table inet sirinvpn_handoff\n",
        "add chain inet sirinvpn_handoff recovery_input { type filter hook input priority -32; policy accept; }\n",
        "add chain inet sirinvpn_handoff recovery_forward { type filter hook forward priority -32; policy accept; }\n",
        "flush chain inet sirinvpn_handoff recovery_input\n",
        "flush chain inet sirinvpn_handoff recovery_forward\n",
    ).to_owned();
    if enabled {
        batch.push_str(&format!(concat!(
            "add rule inet sirinvpn_handoff recovery_input iifname \"{interface}\" ip daddr {address} tcp dport {port} accept\n",
            "add rule inet sirinvpn_handoff recovery_input iifname \"{interface}\" drop\n",
            "add rule inet sirinvpn_handoff recovery_forward iifname \"{interface}\" drop\n",
            "add rule inet sirinvpn_handoff recovery_forward oifname \"{interface}\" drop\n"
        ), interface=configuration.interface_name, address=configuration.server_tunnel_address, port=configuration.management_port));
    }
    batch
}

mod journal;
#[cfg(test)]
mod tests;
