use super::*;
use std::fs;

pub(super) fn read_member_policy(path: &Path) -> Result<sirinvpn_protocol::MemberPolicy> {
    let bytes = fs::read(path).context("could not read the member policy file")?;
    if bytes.len() > 16 * 1024 {
        bail!("the member policy is too large");
    }
    let policy: sirinvpn_protocol::MemberPolicy = serde_json::from_slice(&bytes)?;
    policy.validate().map_err(anyhow::Error::msg)?;
    Ok(policy)
}

pub(super) async fn set_member_policy(
    paths: &ClientPaths,
    arguments: MemberPolicyArguments,
    json: bool,
) -> Result<()> {
    let policy = read_member_policy(&arguments.policy_file)?;
    let member_id = arguments.member_id.parse::<MemberId>()?;
    let client = lifecycle_client(paths, &arguments.server).await?;
    if !client.configuration().await?.member_policies_enabled {
        bail!("update the VPS before configuring member policies");
    }
    let snapshot = client.update_member_policy(member_id, &policy).await?;
    print_membership(&snapshot, json)
}

async fn lifecycle_client(paths: &ClientPaths, selector: &str) -> Result<ManagementClient> {
    let (profile, secret) = connected_identity(paths, selector)?;
    let client = ManagementClient::new(&profile, &secret)?;
    if !client.configuration().await?.member_lifecycle_enabled {
        bail!("update the VPS before managing member suspension or revoking all member devices");
    }
    Ok(client)
}

pub(super) async fn set_member_suspension(
    paths: &ClientPaths,
    selector: MemberSelector,
    suspended: bool,
    json: bool,
) -> Result<()> {
    let member_id = selector
        .member_id
        .parse::<MemberId>()
        .context("member identifier is invalid")?;
    let snapshot = lifecycle_client(paths, &selector.server)
        .await?
        .update_member_suspension(member_id, suspended)
        .await?;
    print_membership(&snapshot, json)
}

pub(super) async fn revoke_member_devices(
    paths: &ClientPaths,
    arguments: RevokeMemberDevicesArguments,
    json: bool,
) -> Result<()> {
    if !arguments.confirm_revoke_all {
        bail!(
            "pass --confirm-revoke-all to permanently remove every device and pending enrollment for this member"
        );
    }
    let member_id = arguments
        .member_id
        .parse::<MemberId>()
        .context("member identifier is invalid")?;
    let snapshot = lifecycle_client(paths, &arguments.server)
        .await?
        .revoke_member_devices(member_id, true)
        .await?;
    print_membership(&snapshot, json)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn bulk_revocation_requires_confirmation_before_loading_a_profile_or_connecting() {
        let cli = Cli::try_parse_from([
            "sirinvpn",
            "server",
            "revoke-member-devices",
            "test",
            "member",
        ])
        .unwrap();
        let Commands::Server { command } = cli.command else {
            panic!("wrong command");
        };
        let ServerCommand::RevokeMemberDevices(arguments) = *command else {
            panic!("wrong command");
        };
        let paths = ClientPaths::under(PathBuf::from("/unavailable/sirinvpn-lifecycle-test"));
        let error = revoke_member_devices(&paths, arguments, false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("--confirm-revoke-all"));
        let cli = Cli::try_parse_from([
            "sirinvpn",
            "server",
            "revoke-member-devices",
            "test",
            "member",
            "--confirm-revoke-all",
        ])
        .unwrap();
        let Commands::Server { command } = cli.command else {
            panic!("wrong command");
        };
        assert!(matches!(
            *command,
            ServerCommand::RevokeMemberDevices(RevokeMemberDevicesArguments {
                confirm_revoke_all: true,
                ..
            })
        ));
    }
}
