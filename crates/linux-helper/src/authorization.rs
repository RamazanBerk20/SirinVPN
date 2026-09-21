//! Persistent permission covers only the installed helper's VPN-control actions.
use crate::*;
use nix::unistd::{Uid, User};
use std::os::unix::fs::MetadataExt;

pub const VPN_CONTROL_COMMANDS: &[&str] = &[
    "connect",
    "connect-managed",
    "disconnect",
    "pause-for-key-rotation",
    "resume",
    "pause-session",
    "reconnect-session",
    "switch-session",
    "apply-endpoint-checkpoint",
    "publish-endpoint-checkpoint",
    "disconnect-session",
];

pub fn vpn_control_action(command: &str) -> Option<String> {
    VPN_CONTROL_COMMANDS
        .contains(&command)
        .then(|| format!("org.sirinvpn.network.{command}"))
}

pub fn authorize_invoking_user() -> Result<()> {
    require_root().map_err(anyhow::Error::from)?;
    // pkexec overwrites this variable with the authenticated invoking UID.
    // Never accept a username or UID from stdin or command-line arguments.
    let uid: u32 = std::env::var("PKEXEC_UID")?.parse()?;
    anyhow::ensure!(uid != 0, "an unprivileged caller is required");
    let user = User::from_uid(Uid::from_raw(uid))?
        .ok_or_else(|| anyhow!("the invoking account is unavailable"))?;
    let directory = Path::new("/etc/polkit-1/rules.d");
    fs::create_dir_all(directory)?;
    let metadata = directory.metadata()?;
    anyhow::ensure!(
        metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "the authorization directory must be root-owned and protected"
    );
    system::write_system_file(
        &directory.join(format!("49-sirinvpn-user-{uid}.rules")),
        &authorization_rule(&user.name)?,
    )
}

fn authorization_rule(username: &str) -> Result<String> {
    let username = serde_json::to_string(username)?;
    let actions = serde_json::to_string(
        &VPN_CONTROL_COMMANDS
            .iter()
            .filter_map(|command| vpn_control_action(command))
            .collect::<Vec<_>>(),
    )?;
    Ok(format!(
        "// SirinVPN VPN controls for this account; remove this file to revoke.\n\
         polkit.addRule(function(action, subject) {{\n\
             if (subject.user === {username} && subject.local && subject.active &&\n\
                 {actions}.indexOf(action.id) !== -1) {{\n\
                 return polkit.Result.YES;\n\
             }}\n\
         }});\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembered_permission_excludes_administration_and_quotes_account_names() {
        for command in [
            "install-system",
            "authorize-user",
            "supervise",
            "relay",
            "measure-session",
            "launch-application",
            "application-child",
            "connect --help",
        ] {
            assert!(vpn_control_action(command).is_none());
        }
        let rule = authorization_rule("name\"; injected()").unwrap();
        assert!(rule.contains(r#"subject.user === "name\"; injected()""#));
        assert!(rule.contains("subject.local && subject.active"));
        for command in VPN_CONTROL_COMMANDS {
            let action = vpn_control_action(command).unwrap();
            assert!(rule.contains(&action));
            assert!(POLKIT_POLICY.contains(&format!("id=\"{action}\"")));
            assert!(POLKIT_POLICY.contains(&format!(
                "key=\"org.freedesktop.policykit.exec.argv1\">{command}</annotate>"
            )));
        }
    }
}
