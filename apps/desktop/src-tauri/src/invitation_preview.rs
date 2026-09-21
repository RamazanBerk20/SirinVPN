use serde::Serialize;
use sirinvpn_core::{DecodedInvitation, management_certificate_fingerprint};
use zeroize::Zeroizing;

#[derive(Serialize)]
pub(crate) struct InvitationPreview {
    server_name: String,
    host: String,
    server_identity_fingerprint: String,
    expires_at_unix: u64,
    recipient_names: bool,
    creates_member: bool,
    member_name: String,
    device_name: String,
    access_level: &'static str,
}

/// Validate the full signed code locally before exposing review fields. Never enroll here.
#[tauri::command]
pub(crate) fn preview_invitation(code: String) -> Result<InvitationPreview, String> {
    let code = Zeroizing::new(code);
    let invitation = DecodedInvitation::decode(&code)
        .map_err(|_| "This invitation is invalid, expired, modified, or unsupported.".to_owned())?;
    let binding = invitation.enrollment_binding();
    Ok(InvitationPreview {
        server_name: invitation.server_name().to_owned(),
        host: binding.endpoint.host,
        server_identity_fingerprint: management_certificate_fingerprint(
            &binding.pinned_server_certificate_pem,
        )
        .map_err(|_| "The invitation's server identity could not be verified.".to_owned())?,
        expires_at_unix: invitation.expires_at_unix(),
        recipient_names: invitation.recipient_names(),
        creates_member: invitation.creates_member(),
        member_name: invitation.member_name().to_owned(),
        device_name: invitation.device_name().to_owned(),
        access_level: if binding.role == sirinvpn_protocol::ServerRole::Owner {
            "owner"
        } else if invitation.administrator() {
            "admin"
        } else {
            "member"
        },
    })
}
