//! Access.

use super::*;

pub(super) async fn authorize_device(
    state: &AppState,
    caller: &CallerIdentity,
    manager_required: bool,
) -> Result<CallerAuthorization, ApiError> {
    let authorization = match &state.authorization {
        Some(authorization) => {
            let authorization = authorization.read().await;
            return authorize_current(&authorization, caller, manager_required);
        }
        None => {
            let owner = certificate_fingerprint(&state.configuration.owner_certificate_pem)
                .map_err(|_| ApiError::internal())?;
            if owner != caller.certificate_fingerprint {
                return Err(ApiError::forbidden());
            }
            CallerAuthorization {
                role: ServerRole::Owner,
                administrator: false,
                device_id: None,
                wireguard_public_key: None,
            }
        }
    };
    if manager_required && !authorization.can_manage() {
        return Err(ApiError::forbidden());
    }
    Ok(authorization)
}

/// Mutations call this while holding the authorization write lock, so an
/// already-open request cannot act on a revoked, suspended or demoted identity.
pub(super) fn authorize_current(
    authorization: &AuthorizationDocument,
    caller: &CallerIdentity,
    manager_required: bool,
) -> Result<CallerAuthorization, ApiError> {
    let device = authorization
        .device_for_fingerprint(&caller.certificate_fingerprint)
        .ok_or_else(ApiError::forbidden)?;
    let access = authorization
        .access_for_device(device)
        .ok_or_else(ApiError::forbidden)?;
    let caller = CallerAuthorization {
        role: access.role,
        administrator: access.administrator,
        device_id: Some(device.id),
        wireguard_public_key: decode_key(&device.wireguard_public_key).ok(),
    };
    if manager_required && !caller.can_manage() {
        return Err(ApiError::forbidden());
    }
    Ok(caller)
}

/// Authorization commits a device without manager rights may make per minute. Each commit
/// that removes access briefly contains every device's traffic and holds the write lock.
pub(super) const MEMBER_MUTATIONS_PER_MINUTE: usize = 10;
/// All of one person's devices together. Twice one device's budget leaves room to act from a
/// phone and a laptop in the same minute, while a person with many devices cannot multiply
/// the server-wide containment and write-lock holds the per-device budget bounds.
pub(super) const MEMBER_WIDE_MUTATIONS_PER_MINUTE: usize = 2 * MEMBER_MUTATIONS_PER_MINUTE;
pub(super) const STATUS_STREAMS_PER_DEVICE: usize = 2;

/// Budgets follow the stable ids, never the certificate fingerprint a key rotation replaces.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum Budget {
    Device(DeviceId),
    Member(MemberId),
}

/// Process-local request budgets; nothing here is persisted.
#[derive(Clone, Default)]
pub(super) struct Throttle {
    mutations: Arc<Mutex<HashMap<Budget, VecDeque<Instant>>>>,
    streams: Arc<Mutex<HashMap<String, usize>>>,
    pub(super) status: super::status_stream::StatusFeed,
}

/// Call with the write lock held, before any work, in every mutating handler a Member can reach.
/// Owners and Admins are not limited: they can already remove every device.
pub(super) fn limit_mutation(
    state: &AppState,
    authorization: &AuthorizationDocument,
    caller: &CallerIdentity,
) -> Result<(), ApiError> {
    let fingerprint = &caller.certificate_fingerprint;
    // Committing or cancelling a key rotation comes from the new identity, which owns no
    // device yet: charge the device being rotated.
    let device = authorization
        .device_for_fingerprint(fingerprint)
        .or_else(|| {
            let rotation = authorization
                .key_rotations
                .iter()
                .find(|rotation| rotation.new_certificate_fingerprint == *fingerprint)?;
            authorization.devices.iter().find(|device| {
                device.id == rotation.device_id
                    && device.certificate_fingerprint == rotation.previous_certificate_fingerprint
            })
        });
    // Unknown identities get their usual 403 from the handler; managers are not limited.
    let Some((device, access)) =
        device.and_then(|device| Some((device, authorization.access_for_device(device)?)))
    else {
        return Ok(());
    };
    if access.role == ServerRole::Owner || access.administrator {
        return Ok(());
    }
    let now = Instant::now();
    let mut budgets = state
        .throttle
        .mutations
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    budgets.retain(|_, times| {
        times.retain(|time| now.duration_since(*time) < Duration::from_secs(60));
        !times.is_empty()
    });
    let charged = [
        (Budget::Device(device.id), MEMBER_MUTATIONS_PER_MINUTE),
        (
            Budget::Member(device.member_id),
            MEMBER_WIDE_MUTATIONS_PER_MINUTE,
        ),
    ];
    if charged.iter().any(|(budget, limit)| {
        budgets
            .get(budget)
            .is_some_and(|times| times.len() >= *limit)
    }) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::RateLimited,
            "this device made too many changes; try again in a minute",
        ));
    }
    for (budget, _) in charged {
        budgets.entry(budget).or_default().push_back(now);
    }
    Ok(())
}

/// Held by an open status stream; dropping it frees the slot.
pub(super) struct StreamSlot {
    streams: Arc<Mutex<HashMap<String, usize>>>,
    fingerprint: String,
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        let mut streams = self
            .streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = streams.get_mut(&self.fingerprint) {
            *count -= 1;
            if *count == 0 {
                streams.remove(&self.fingerprint);
            }
        }
    }
}

pub(super) fn acquire_stream(
    state: &AppState,
    caller: &CallerIdentity,
) -> Result<StreamSlot, ApiError> {
    let mut streams = state
        .throttle
        .streams
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let count = streams
        .entry(caller.certificate_fingerprint.clone())
        .or_default();
    if *count >= STATUS_STREAMS_PER_DEVICE {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::RateLimited,
            "this device already has open status streams",
        ));
    }
    *count += 1;
    Ok(StreamSlot {
        streams: state.throttle.streams.clone(),
        fingerprint: caller.certificate_fingerprint.clone(),
    })
}

pub(super) fn can_manage_member(
    caller: CallerAuthorization,
    role: ServerRole,
    administrator: bool,
) -> bool {
    caller.is_owner() || (caller.administrator && role == ServerRole::Member && !administrator)
}

/// Adding a device to `target`: any member the caller manages; their own member when the
/// caller is an Admin or holds the delegated permission. Limits and suspension are checked
/// separately and still apply.
pub(super) fn can_add_device_to(
    caller: CallerAuthorization,
    caller_member_id: MemberId,
    target: &MemberRecord,
) -> bool {
    can_manage_member(caller, target.role, target.administrator)
        || (target.id == caller_member_id
            && (caller.administrator || target.policy.add_own_devices))
}

pub(super) fn caller_member(
    authorization: &AuthorizationDocument,
    caller: CallerAuthorization,
) -> Option<&MemberRecord> {
    let device = authorization
        .devices
        .iter()
        .find(|device| Some(device.id) == caller.device_id)?;
    authorization
        .members
        .iter()
        .find(|member| member.id == device.member_id)
}

pub(super) fn filtered_snapshot(
    authorization: &AuthorizationDocument,
    caller: CallerAuthorization,
) -> MembershipSnapshot {
    let mut snapshot = authorization.snapshot(unix_time());
    if !caller.can_manage() {
        let member_id = caller_member(authorization, caller).map(|member| member.id);
        snapshot
            .members
            .retain(|member| Some(member.id) == member_id);
        snapshot.active_invitations.retain(|summary| {
            authorization.invitations.iter().any(|grant| {
                grant.claims.invitation_id == summary.id
                    && grant.issued_by == member_id
                    && member_id.is_some()
            })
        });
        let own = |device_id: DeviceId| {
            authorization
                .devices
                .iter()
                .any(|device| device.id == device_id && Some(device.member_id) == member_id)
        };
        snapshot
            .port_forwards
            .retain(|forward| own(forward.device_id));
        // A member learns who may reach their devices, not the rest of the server's pairs.
        snapshot
            .device_pairs
            .retain(|pair| own(pair.device_id) || own(pair.peer_device_id));
    }
    snapshot
}

pub(super) fn require_authorization(
    state: &AppState,
) -> Result<Arc<RwLock<AuthorizationDocument>>, ApiError> {
    state.authorization.clone().ok_or_else(|| {
        ApiError::conflict(
            "P1 authorization state is not initialized; run the compatible owner upgrade first",
        )
    })
}

pub(super) async fn commit_authorization(
    state: &AppState,
    current: &mut AuthorizationDocument,
    next: AuthorizationDocument,
) -> Result<(), ApiError> {
    authorization_transaction::commit(
        &authorization_transaction::Host(state),
        &state.recovery,
        current,
        next,
    )
    .await
}

pub(super) fn decoded_transport_peers(
    authorization: &AuthorizationDocument,
) -> Result<Vec<[u8; 32]>> {
    // WireGuard-only devices reach Direct UDP alone; the relays never authenticate them.
    let direct_only: HashSet<_> = authorization
        .devices
        .iter()
        .filter(|device| device.wireguard_only())
        .map(|device| device.wireguard_public_key.as_str())
        .collect();
    authorization
        .desired_peers(unix_time())
        .into_iter()
        .filter(|peer| !direct_only.contains(peer.public_key.as_str()))
        .map(|peer| {
            decode_key(&peer.public_key)
                .map_err(|_| anyhow!("authorization contains an invalid transport peer"))
        })
        .collect()
}
