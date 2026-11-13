//! The authorization write lock owns transactions and recovery. Dirty is set before
//! the first await and only cleared after durable authority and every effect agree.
use super::*;
use sirinvpn_protocol::{AuthorizationHealth, AuthorizationRecovery};

/// What the kernel, transport and durable authority look like right now. Owned by the
/// authorization write lock; every transition below happens while it is held.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Phase {
    /// Every effect agrees with the in-memory document. `applied` is what was enforced
    /// (absent before the first apply or when it could not be computed).
    Healthy { applied: Option<Footprint> },
    /// An intent is durable and effects are being changed. `committed` once the new
    /// document is durable; `contained` while the drop rules are verified installed.
    Applying { contained: bool, committed: bool },
    /// Effects or authority are uncertain; the next recovery attempt restores them.
    RecoveryPending { contained: bool, committed: bool },
    /// The last recovery attempt failed; containment stays until one succeeds.
    RecoveryFailed { contained: bool, committed: bool },
}

impl Default for Phase {
    fn default() -> Self {
        Self::Healthy { applied: None }
    }
}

#[derive(Default)]
pub(super) struct RecoveryState {
    pub generation: u64,
    pub phase: Phase,
    /// Consecutive failed periodic attempts and when the next one is due.
    pub failures: u32,
    pub retry_at: Option<Instant>,
}

impl RecoveryState {
    /// The wire shape older clients already understand.
    pub(super) fn wire(&self) -> AuthorizationRecovery {
        let (health, containment_verified, committed) = match self.phase {
            Phase::Healthy { .. } => (AuthorizationHealth::Healthy, false, false),
            Phase::Applying {
                contained,
                committed,
            } => (AuthorizationHealth::Applying, contained, committed),
            Phase::RecoveryPending {
                contained,
                committed,
            } => (AuthorizationHealth::RecoveryPending, contained, committed),
            Phase::RecoveryFailed {
                contained,
                committed,
            } => (AuthorizationHealth::RecoveryFailed, contained, committed),
        };
        AuthorizationRecovery {
            health,
            generation: self.generation,
            containment_verified,
            committed,
        }
    }

    fn contained(&mut self, value: bool) {
        if let Phase::Applying { contained, .. }
        | Phase::RecoveryPending { contained, .. }
        | Phase::RecoveryFailed { contained, .. } = &mut self.phase
        {
            *contained = value;
        }
    }

    fn flags(&self) -> (bool, bool) {
        match self.phase {
            Phase::Healthy { .. } => (false, false),
            Phase::Applying {
                contained,
                committed,
            }
            | Phase::RecoveryPending {
                contained,
                committed,
            }
            | Phase::RecoveryFailed {
                contained,
                committed,
            } => (contained, committed),
        }
    }

    fn pending(&mut self) {
        let (contained, committed) = self.flags();
        self.phase = Phase::RecoveryPending {
            contained,
            committed,
        };
    }

    fn failed(&mut self) {
        let (contained, committed) = self.flags();
        self.phase = Phase::RecoveryFailed {
            contained,
            committed,
        };
    }
}

/// Everything a document enforces, as the stages render it. Comparing two of them tells
/// whether a change only adds access (no containment needed) or may take some away.
#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct Footprint {
    pub peers: Vec<DesiredPeer>,
    pub transport: Vec<[u8; 32]>,
    pub isolation: PeerIsolationState,
    pub forwarding: Option<String>,
    pub handoff_source: bool,
}

pub(super) fn footprint(
    configuration: &ServerConfiguration,
    operational: Option<&OperationalConfiguration>,
    document: &AuthorizationDocument,
) -> Result<Footprint> {
    Ok(Footprint {
        peers: document.desired_peers(unix_time()),
        transport: decoded_transport_peers(document)?,
        isolation: peer_isolation_state(configuration, document)?,
        forwarding: port_forward_nft_batch(configuration, operational, document)?,
        handoff_source: document.endpoint.is_handoff_source(),
    })
}

/// True unless `next` keeps every enforced grant of `applied` unchanged and only adds new
/// ones. A changed peer (key, PSK, address, routes) counts as removal, and a new peer
/// carrying routes or reusing an address could take traffic from an existing one.
///
/// One exception: a peer whose public key alone was replaced, at the same address with the
/// same routes (a key rotation), keeps every grant. Containment adds nothing to removing the
/// old key: the Wireguard stage swaps it in a single `wg set` before Persist, so the old key
/// is gone before the commit is durable or answered; any failed stage recovers under
/// containment; and containment never covered the relays (it drops only on the tunnel
/// interface), which pass the old key's packets to a WireGuard that no longer has its peer.
pub(super) fn narrows(applied: &Footprint, next: &Footprint) -> bool {
    let addresses: HashSet<IpAddr> = applied.peers.iter().map(|peer| peer.address).collect();
    let added: Vec<&DesiredPeer> = next
        .peers
        .iter()
        .filter(|peer| !applied.peers.contains(peer))
        .collect();
    let at = |peers: &[DesiredPeer], address: IpAddr| {
        peers.iter().filter(|peer| peer.address == address).count()
    };
    let replacement = |old: &DesiredPeer| {
        added
            .iter()
            .copied()
            .find(|new| new.address == old.address && new.subnet_routes == old.subnet_routes)
            .filter(|_| {
                at(&applied.peers, old.address) == 1
                    && at(&next.peers, old.address) == 1
                    && !next
                        .peers
                        .iter()
                        .any(|peer| peer.public_key == old.public_key)
            })
    };
    let mut replaced_keys = HashSet::new();
    let mut replacements = HashSet::new();
    for old in applied
        .peers
        .iter()
        .filter(|peer| !next.peers.contains(peer))
    {
        let Some(new) = replacement(old) else {
            return true;
        };
        replaced_keys.insert(old.public_key.as_str());
        replacements.insert(new.public_key.as_str());
    }
    let added_peers_are_isolated = added.iter().all(|peer| {
        replacements.contains(peer.public_key.as_str())
            || (peer.subnet_routes.is_empty() && !addresses.contains(&peer.address))
    });
    let replaced_transport: HashSet<[u8; 32]> = replaced_keys
        .iter()
        .filter_map(|key| decode_key(key).ok())
        .collect();
    // The forwarding chain holds only accept rules ahead of isolation; flushes are framing.
    let rules = |batch: &Option<String>| -> HashSet<String> {
        batch
            .iter()
            .flat_map(|batch| batch.lines())
            .filter(|line| !line.starts_with("flush "))
            .map(str::to_owned)
            .collect()
    };
    let kept = applied
        .transport
        .iter()
        .all(|key| next.transport.contains(key) || replaced_transport.contains(key))
        && applied
            .isolation
            .ipv4
            .iter()
            .all(|address| next.isolation.ipv4.contains(address))
        && applied
            .isolation
            .ipv6
            .iter()
            .all(|address| next.isolation.ipv6.contains(address))
        && applied.handoff_source == next.handoff_source
        && applied.forwarding.is_some() == next.forwarding.is_some()
        && rules(&applied.forwarding).is_subset(&rules(&next.forwarding));
    !(kept && added_peers_are_isolated)
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
    /// Unknown footprints always contain.
    fn footprint(&self, _document: &AuthorizationDocument) -> Result<Footprint> {
        bail!("authorization footprint is not modeled")
    }
}

fn lock(state: &Mutex<RecoveryState>) -> std::sync::MutexGuard<'_, RecoveryState> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

pub(super) fn status(state: &Mutex<RecoveryState>) -> AuthorizationRecovery {
    lock(state).wire()
}

pub(super) fn needs_recovery(state: &Mutex<RecoveryState>) -> bool {
    !matches!(lock(state).phase, Phase::Healthy { .. })
}

fn healthy(io: &impl Effects, state: &Mutex<RecoveryState>, document: &AuthorizationDocument) {
    let applied = io.footprint(document).ok();
    lock(state).phase = Phase::Healthy { applied };
}

/// The in-memory document is enforced exactly as `next` would be: committing it is a no-op.
pub(super) fn is_applied(
    io: &impl Effects,
    state: &Mutex<RecoveryState>,
    current: &AuthorizationDocument,
    next: &AuthorizationDocument,
) -> bool {
    let Phase::Healthy {
        applied: Some(applied),
    } = &lock(state).phase
    else {
        return false;
    };
    current == next
        && io
            .footprint(next)
            .is_ok_and(|footprint| footprint == *applied)
}

/// Whether the periodic loop may try again now.
pub(super) fn retry_due(state: &Mutex<RecoveryState>) -> bool {
    lock(state)
        .retry_at
        .is_none_or(|retry_at| Instant::now() >= retry_at)
}

/// Exponential backoff (2–32 s) for the periodic loop after failures.
pub(super) fn record_attempt(state: &Mutex<RecoveryState>, succeeded: bool) {
    let mut state = lock(state);
    if succeeded {
        state.failures = 0;
        state.retry_at = None;
    } else {
        state.failures = state.failures.saturating_add(1).min(5);
        state.retry_at = Some(Instant::now() + Duration::from_secs(1 << state.failures));
    }
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
    let generation = {
        let mut state = lock(state);
        state.pending();
        state.generation
    };
    let contained = io.execute(Stage::Contain, current).await.is_ok();
    lock(state).contained(contained);
    if !contained {
        lock(state).failed();
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
        lock(state).contained(false);
        io.execute(Stage::Complete, current).await
    }
    .await;
    if lock(state).generation == generation {
        if restored.is_ok() {
            healthy(io, state, current);
        } else {
            lock(state).failed();
        }
    }
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
    if is_applied(io, state, current, &next) {
        // Nothing to enforce: no intent, no containment, no kernel work.
        return Ok(());
    }
    // Containment only guards against access outliving its removal. A pure addition
    // that fails part-way still recovers under containment below.
    let contain = {
        let applied = match &lock(state).phase {
            Phase::Healthy { applied } => applied.clone(),
            _ => None,
        };
        match (applied, io.footprint(&next)) {
            (Some(applied), Ok(next)) => narrows(&applied, &next),
            _ => true,
        }
    };
    let generation = {
        let mut state = lock(state);
        state.generation = state.generation.saturating_add(1);
        state.phase = Phase::Applying {
            contained: false,
            committed: false,
        };
        state.generation
    };
    if io.intent(current, &next, generation).is_err() {
        lock(state).pending();
        return Err(recovery_error(false));
    }
    if contain {
        if io.execute(Stage::Contain, current).await.is_err() {
            lock(state).failed();
            return Err(recovery_error(false));
        }
        lock(state).contained(true);
    }
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
        if let Phase::Applying { committed: c, .. } = &mut lock(state).phase {
            *c = committed;
        }
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
    if let Phase::Applying { committed, .. } = &mut lock(state).phase {
        *committed = true;
    }
    let published = publish(io, current).await;
    lock(state).contained(false);
    if !published || io.execute(Stage::Complete, current).await.is_err() {
        lock(state).pending();
        return Err(recovery_error(true));
    }
    healthy(io, state, current);
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
        .endpoint
        .head()
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
        // Root maintenance (`init` during repair) can replace the file while this process
        // holds an older copy. Committing would silently discard that change; failing here
        // sends the commit into recovery, which adopts the durable document instead.
        let durable = load_authorization(&self.0.paths.authorization)?;
        if fingerprint(&durable)? != fingerprint(previous)? {
            bail!("authorization state changed outside this process");
        }
        journal::write(&self.0.paths, previous, next, generation)
    }
    fn authority(&self) -> Result<AuthorizationDocument> {
        journal::validate(&self.0.paths)?;
        load_authorization(&self.0.paths.authorization)
    }
    fn footprint(&self, document: &AuthorizationDocument) -> Result<Footprint> {
        footprint(
            &self.0.configuration,
            self.0.operational_configuration.as_ref(),
            document,
        )
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

pub(super) mod journal;
#[cfg(test)]
mod tests;
