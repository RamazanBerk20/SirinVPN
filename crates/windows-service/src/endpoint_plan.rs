use crate::{ServiceError, network_plan};
use sirinvpn_protocol::{EndpointTransitionResponse, MtuPolicy};
use sirinvpn_transport::TransportEngine;
use sirinvpn_tunnel_model::{TunnelConnectRequest, policy_transport_candidates};

/// Cryptographic validation precedes use of every hostname, port, and TLS pin.
/// A server handoff may update its network descriptor, never the client's policy.
pub(crate) fn replacement(
    base: &TunnelConnectRequest,
    head: &EndpointTransitionResponse,
) -> Result<TunnelConnectRequest, ServiceError> {
    let known = base
        .endpoint_identity
        .as_ref()
        .ok_or(ServiceError::InvalidRequest)?;
    let updated = sirinvpn_core::verify_endpoint_checkpoint(known, head)
        .map_err(|_| ServiceError::InvalidRequest)?;
    let kinds = if base.reconnect_candidates.is_empty() {
        vec![base.transport]
    } else {
        base.reconnect_candidates
            .iter()
            .map(|candidate| candidate.transport)
            .collect()
    };
    let mut selections = kinds
        .into_iter()
        .filter_map(|kind| {
            TransportEngine
                .select_descriptor(&updated.descriptor, kind)
                .ok()
        })
        .collect::<Vec<_>>();
    if selections.is_empty() {
        return Err(ServiceError::InvalidRequest);
    }
    if let Some(MtuPolicy::Manual { value }) = base.mtu_policy {
        for selection in &mut selections {
            selection.mtu = value;
        }
    }
    let offset = selections
        .iter()
        .position(|selection| selection.kind == base.transport)
        .unwrap_or(0);
    selections.rotate_left(offset);
    let selection = &selections[0];
    let mut request = base.clone();
    request.schema_version = 10;
    request.endpoint_host = selection.network_endpoint.host.clone();
    request.endpoint_port = selection.network_endpoint.wireguard_port;
    request.transport = selection.kind;
    request.server_transport_public_key = selection.server_transport_public_key.clone();
    request.server_certificate_sha256 = selection.server_certificate_sha256.clone();
    request.https = selection.https.clone();
    request.mtu = selection.mtu;
    request.reconnect_candidates = policy_transport_candidates(&selections);
    request.client_ipv6_address =
        if request.client_address.octets()[3] < 224 && updated.descriptor.ipv6_tunnel_enabled {
            sirinvpn_protocol::ipv6_tunnel_address(request.server_id, request.client_address)
        } else {
            None
        };
    request.endpoint_checkpoint = Some(head.clone());
    request.endpoint_identity = Some(updated);
    network_plan::validate(&request)?;
    Ok(request)
}
