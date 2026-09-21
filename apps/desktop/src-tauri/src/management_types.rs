use serde::{Deserialize, Serialize};
use sirinvpn_protocol::{InvitationId, PortForwardProtocol};
use zeroize::Zeroize;

#[derive(Deserialize)]
pub(super) struct InvitationInput {
    #[serde(default)]
    pub(super) recipient_names: bool,
    pub(super) server_id: String,
    pub(super) member_name: String,
    pub(super) device_name: String,
    pub(super) target_member_id: Option<String>,
    pub(super) administrator: bool,
    #[serde(default)]
    pub(super) max_uses: Option<u16>,
    #[serde(default)]
    pub(super) member_policy: sirinvpn_protocol::MemberPolicy,
    pub(super) expires_in_seconds: u32,
}

#[derive(Serialize)]
pub(super) struct InvitationResult {
    pub(super) invitation_id: InvitationId,
    pub(super) expires_at_unix: u64,
    pub(super) code: String,
    pub(super) qr_svg: String,
}

impl Drop for InvitationResult {
    fn drop(&mut self) {
        self.code.zeroize();
        self.qr_svg.zeroize();
    }
}

#[derive(Deserialize)]
pub(super) struct DeviceRenameInput {
    pub(super) server_id: String,
    pub(super) device_id: String,
    pub(super) name: String,
}

#[derive(Deserialize)]
pub(super) struct DevicePeerCommunicationInput {
    pub(super) server_id: String,
    pub(super) device_id: String,
    pub(super) enabled: bool,
}

#[derive(Deserialize)]
pub(super) struct PortForwardCreateInput {
    pub(super) server_id: String,
    pub(super) protocol: PortForwardProtocol,
    pub(super) public_port: u16,
    pub(super) device_id: String,
    pub(super) device_port: u16,
    pub(super) confirmed: bool,
}

#[derive(Deserialize)]
pub(super) struct PortForwardRemoveInput {
    pub(super) server_id: String,
    pub(super) protocol: PortForwardProtocol,
    pub(super) public_port: u16,
}

#[derive(Deserialize)]
pub(super) struct MemberAccessInput {
    pub(super) server_id: String,
    pub(super) member_id: String,
    pub(super) administrator: bool,
}

#[derive(Deserialize)]
pub(super) struct OwnershipTransferInput {
    pub(super) server_id: String,
    pub(super) destination_device_id: String,
    pub(super) confirmed: bool,
}
