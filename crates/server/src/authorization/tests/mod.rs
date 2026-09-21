use super::*;

use serde::Deserialize;

use sirinvpn_core::LocalIdentity;

use sirinvpn_protocol::{DEFAULT_MANAGEMENT_PORT, ServerEndpoint};

fn state() -> AuthorizationDocument {
    let owner = LocalIdentity::generate("Owner").unwrap();
    AuthorizationDocument::new_owner(
        ServerId::new(),
        owner.public.wireguard_public_key,
        owner.public.management_certificate_pem,
    )
    .unwrap()
}

fn add_member(
    state: &mut AuthorizationDocument,
    name: &str,
    administrator: bool,
) -> (MemberId, LocalIdentity) {
    let member_id = MemberId::new();
    let identity = LocalIdentity::generate(name).unwrap();
    let address = state.allocate_member_address().unwrap();
    state.members.push(MemberRecord {
        policy: Default::default(),
        id: member_id,
        name: name.to_owned(),
        role: ServerRole::Member,
        administrator,
        suspended: false,
    });
    state.devices.push(DeviceRecord {
        id: DeviceId::new(),
        member_id,
        name: format!("{name} device"),
        client_tunnel_address: address,
        wireguard_public_key: identity.public.wireguard_public_key.clone(),
        management_certificate_pem: identity.public.management_certificate_pem.clone(),
        certificate_fingerprint: certificate_fingerprint(
            &identity.public.management_certificate_pem,
        )
        .unwrap(),
        peer_communication_enabled: false,
    });
    (member_id, identity)
}

mod member_lifecycle;
mod member_policy;
mod owner_state_is_valid_and_uses_the_legacy_address;
mod ownership_transfer_is_atomic_and_keeps_a_single_owner;
