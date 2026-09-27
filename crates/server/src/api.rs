//! Api.

use super::*;

#[derive(Clone)]
pub(super) struct CallerIdentity {
    pub(super) certificate_fingerprint: String,
}

#[derive(Clone, Copy)]
pub(super) struct CallerAuthorization {
    pub(super) role: ServerRole,
    pub(super) administrator: bool,
    pub(super) device_id: Option<DeviceId>,
    pub(super) wireguard_public_key: Option<[u8; 32]>,
}

impl CallerAuthorization {
    pub(super) fn can_manage(self) -> bool {
        self.role == ServerRole::Owner || self.administrator
    }

    pub(super) fn is_owner(self) -> bool {
        self.role == ServerRole::Owner
    }
}

#[derive(Debug)]
pub(super) struct ApiError {
    pub(super) status: StatusCode,
    pub(super) code: ErrorCode,
    pub(super) message: String,
}

impl ApiError {
    pub(super) fn new(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub(super) fn forbidden() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            ErrorCode::AuthorizationFailed,
            "this device is not authorized for that operation",
        )
    }

    pub(super) fn invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorCode::InvalidInput, message)
    }

    pub(super) fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, ErrorCode::ConflictDetected, message)
    }

    pub(super) fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::InstallationFailed,
            "the server could not safely commit the authorization change",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiErrorBody {
                api_version: API_VERSION.to_owned(),
                code: self.code,
                message: self.message,
            }),
        )
            .into_response()
    }
}

pub(super) fn management_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/status", get(status_handler))
        .route(
            "/v1/measurements",
            post(super::measurement::create).delete(super::measurement::remove),
        )
        .route(
            "/v1/status/stream",
            get(super::status_stream::status_stream_handler),
        )
        .route("/v1/diagnostics", get(diagnostics_handler))
        .route("/v1/configuration", get(configuration_handler))
        .route(
            "/v1/endpoint-transition",
            get(endpoint_transition_handler)
                .post(create_endpoint_transition_handler)
                .put(publish_endpoint_transition_handler),
        )
        .route("/v1/invitations", post(create_invitation_handler))
        .route(
            "/v1/invitations/{invitation_id}",
            delete(cancel_invitation_handler),
        )
        .route("/v1/enrollment", post(enrollment_handler))
        .route("/v1/membership", get(membership_handler))
        .route(
            "/v1/recovery",
            get(super::recovery::settings_handler).patch(super::recovery::policy_handler),
        )
        .route(
            "/v1/recovery/key",
            axum::routing::put(super::recovery::create_key_handler),
        )
        .route(
            "/v1/recovery/key/{recovery_id}",
            delete(super::recovery::revoke_key_handler),
        )
        .route(
            "/v1/recovery/enrollment",
            post(super::recovery::enroll_handler),
        )
        .route(
            "/v1/devices/{device_id}",
            patch(rename_device_handler).delete(revoke_device_handler),
        )
        .route(
            "/v1/devices/{device_id}/peer-communication",
            patch(update_device_peer_communication_handler),
        )
        .route("/v1/port-forwards", post(create_port_forward_handler))
        .route(
            "/v1/port-forwards/{protocol}/{public_port}",
            delete(delete_port_forward_handler),
        )
        .route(
            "/v1/members/{member_id}/access",
            patch(update_member_access_handler),
        )
        .route(
            "/v1/members/{member_id}/policy",
            patch(super::member_lifecycle::update_member_policy_handler),
        )
        .route(
            "/v1/members/{member_id}/suspension",
            patch(update_member_suspension_handler),
        )
        .route(
            "/v1/members/{member_id}/devices",
            delete(revoke_member_devices_handler),
        )
        .route("/v1/ownership", patch(transfer_ownership_handler))
        .route("/v1/key-rotations", post(prepare_key_rotation_handler))
        .route(
            "/v1/key-rotations/{rotation_id}",
            patch(commit_key_rotation_handler).delete(cancel_key_rotation_handler),
        )
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state)
}

pub(super) async fn status_handler(
    State(state): State<AppState>,
    Extension(caller_identity): Extension<CallerIdentity>,
) -> Result<Json<ApiEnvelope<ServerStatus>>, ApiError> {
    caller_status(&state, &caller_identity, state.live_metrics.as_ref())
        .await
        .map(|status| Json(ApiEnvelope::new(status)))
}

pub(super) async fn caller_status(
    state: &AppState,
    caller_identity: &CallerIdentity,
    sampler: &Mutex<LiveMetricSampler>,
) -> Result<ServerStatus, ApiError> {
    let caller = authorize_device(state, caller_identity, false).await?;
    let authorized_keys = match &state.authorization {
        Some(authorization) => {
            let current = authorization.read().await;
            current
                .devices
                .iter()
                .filter(|device| current.access_for_device(device).is_some())
                .map(|device| device.wireguard_public_key.clone())
                .collect::<Vec<_>>()
        }
        None => caller
            .wireguard_public_key
            .into_iter()
            .map(|key| STANDARD.encode(key))
            .collect(),
    };
    let peer_count = authorized_keys.len() as u32;
    let mut status =
        collect_status_with_peer_count(&state.configuration, peer_count, sampler).await;
    if let Some(activity) =
        super::service_metrics::recent_peer_activity(&state.configuration.interface_name).await
    {
        status.recently_active_peer_count =
            super::service_metrics::count_recent_authorized(&activity, &authorized_keys);
    }
    // Collection awaits host processes; recheck access before sending a reading.
    let caller = authorize_device(state, caller_identity, false).await?;
    status.caller_role = Some(caller.role);
    status.caller_administrator = caller.administrator;
    status.caller_device_id = caller.device_id;
    if let Some(transport) = caller.wireguard_public_key.and_then(|public_key| {
        state
            .transport_activity
            .recent_transport(&public_key, Duration::from_secs(45))
    }) {
        status.transport = transport;
    }
    status.caller_identity_fingerprint = caller_identity.certificate_fingerprint.clone();
    status.authorization_recovery = state.authorization.as_ref().map(|_| {
        state
            .recovery
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .status
            .clone()
    });
    if authorization_transaction::needs_recovery(&state.recovery) {
        status.connection_state = ConnectionState::Degraded;
    }
    Ok(status)
}

pub(super) async fn diagnostics_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
) -> Result<Json<ApiEnvelope<DiagnosticReport>>, ApiError> {
    authorize_device(&state, &caller, false).await?;
    let report = collect_diagnostics(&state.configuration).await;
    authorize_device(&state, &caller, false).await?;
    Ok(Json(ApiEnvelope::new(report)))
}

pub(super) async fn configuration_handler(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
) -> Result<Json<ApiEnvelope<CurrentConfiguration>>, ApiError> {
    authorize_device(&state, &caller, false).await?;
    Ok(Json(ApiEnvelope::new(CurrentConfiguration {
        api_version: API_VERSION.to_owned(),
        isolated_measurement_enabled: state.measurement_ready && state.authorization.is_some(),
        interface_name: state.configuration.interface_name.clone(),
        tunnel_cidr: state.configuration.tunnel_cidr.clone(),
        dns_address: state.configuration.server_tunnel_address,
        dns_upstream: state.configuration.dns_upstream.clone(),
        private_dns_records: state.configuration.private_dns_records.clone(),
        wireguard_port: state.configuration.wireguard_port,
        management_port: state.configuration.management_port,
        ipv6_tunnel_enabled: state.configuration.ipv6_tunnel_enabled,
        obfuscated_udp: state.configuration.obfuscated_udp.clone(),
        tcp_fallback: state.configuration.tcp_fallback.clone(),
        tls_like: state.configuration.tls_like.clone(),
        advanced_invitations_enabled: true,
        ownership_transfer_enabled: true,
        key_rotation_enabled: state.authorization.is_some(),
        endpoint_transitions_enabled: state.authorization.is_some(),
        peer_isolation_enabled: state.authorization.is_some(),
        port_forwarding_enabled: state.authorization.is_some()
            && state.operational_configuration.is_some(),
        member_lifecycle_enabled: state.authorization.is_some(),
        member_policies_enabled: state.authorization.is_some(),
        reusable_invitations_enabled: state.authorization.is_some(),
        recipient_names_enabled: state.authorization.is_some(),
        recovery_keys_enabled: state.authorization.is_some(),
    })))
}
