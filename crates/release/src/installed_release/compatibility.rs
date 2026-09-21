use super::*;

pub(super) fn plan_artifact_transition(
    current: &ReleaseManifest,
    candidate: &ReleaseManifest,
    kind: ArtifactKind,
    allow_rollback: bool,
) -> Result<crate::UpdatePlan, ReleaseError> {
    if !matches!(
        kind,
        ArtifactKind::ServerElf | ArtifactKind::WindowsInstaller | ArtifactKind::AndroidApk
    ) {
        return plan_transition(current, candidate, allow_rollback);
    }
    // Desktop/mobile formats do not exist on a VPS. Their migrations must not
    // prevent an otherwise compatible server update. The signed records remain
    // intact; only the already-authenticated compatibility plan is projected.
    let relevant = |state: &crate::StateCompatibility| {
        if kind == ArtifactKind::AndroidApk {
            let name = &state.state;
            return name.starts_with("android_")
                || name.starts_with("client_")
                || name.starts_with("device_")
                || name.starts_with("owner_")
                || name.starts_with("signed_")
                || matches!(
                    name.as_str(),
                    "linux_release_receipt" | "linux_release_trust"
                );
        }
        if kind == ArtifactKind::WindowsInstaller {
            let name = &state.state;
            return name.starts_with("windows_")
                || name.starts_with("desktop_")
                || name.starts_with("device_")
                || name.starts_with("client_")
                || name.starts_with("owner_")
                || name.starts_with("signed_")
                || matches!(
                    name.as_str(),
                    "linux_client_profiles"
                        | "linux_identity_record"
                        | "linux_key_rotation_journal"
                        | "linux_network_policy"
                        | "linux_release_receipt"
                        | "linux_release_trust"
                        | "linux_tunnel_request"
                );
        }
        state.state.starts_with("server_")
            || state.state.starts_with("linux_release_")
            || state.state.starts_with("signed_")
    };
    let mut current = current.clone();
    let mut candidate = candidate.clone();
    current.state_compatibility.retain(&relevant);
    candidate.state_compatibility.retain(&relevant);
    plan_transition(&current, &candidate, allow_rollback)
}
