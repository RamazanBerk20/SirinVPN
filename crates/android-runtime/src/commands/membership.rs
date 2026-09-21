use super::*;
use sirinvpn_core::{InvitationDraft, InvitationTarget};

pub async fn dispatch(
    runtime: &Runtime,
    client: &ManagementClient,
    profile: &ServerProfile,
    command: &str,
    args: &Value,
) -> Result<Value> {
    let input = args.get("input").unwrap_or(args);
    match command {
        "cancel_invitation" => {
            client
                .cancel_invitation(text(args, "invitationId")?.parse()?)
                .await?;
            Ok(Value::Null)
        }
        "rename_device" => encode(
            client
                .rename_device(
                    text(input, "device_id")?.parse()?,
                    text(input, "name")?.to_owned(),
                )
                .await?,
        ),
        "revoke_device" => encode(
            client
                .revoke_device(text(args, "deviceId")?.parse()?)
                .await?,
        ),
        "update_device_peer_communication" => {
            ensure!(
                client.configuration().await?.peer_isolation_enabled,
                "Server needs repair"
            );
            encode(
                client
                    .update_device_peer_communication(
                        text(input, "device_id")?.parse()?,
                        input["enabled"].as_bool().context("Invalid permission")?,
                    )
                    .await?,
            )
        }
        "create_port_forward" => {
            confirmed(input)?;
            ensure!(
                client.configuration().await?.port_forwarding_enabled,
                "Server needs repair"
            );
            let request: PortForwardCreateRequest = serde_json::from_value(
                json!({"protocol":input["protocol"],"public_port":input["public_port"],"device_id":input["device_id"],"device_port":input["device_port"]}),
            )?;
            encode(client.create_port_forward(&request).await?)
        }
        "remove_port_forward" => encode(
            client
                .remove_port_forward(
                    serde_json::from_value(input["protocol"].clone())?,
                    serde_json::from_value(input["public_port"].clone())?,
                )
                .await?,
        ),
        "update_member_access" => {
            ensure!(
                client.status().await?.caller_role == Some(ServerRole::Owner),
                "Only the owner may change Admin access"
            );
            ensure!(
                client.configuration().await?.advanced_invitations_enabled,
                "Update the VPS"
            );
            encode(
                client
                    .update_member_access(
                        text(input, "member_id")?.parse()?,
                        input["administrator"]
                            .as_bool()
                            .context("Invalid permission")?,
                    )
                    .await?,
            )
        }
        "update_member_suspension" => {
            ensure!(
                client.configuration().await?.member_lifecycle_enabled,
                "Update the VPS"
            );
            encode(
                client
                    .update_member_suspension(
                        text(input, "member_id")?.parse()?,
                        input["suspended"].as_bool().context("Invalid suspension")?,
                    )
                    .await?,
            )
        }
        "update_member_policy" => {
            ensure!(
                client.configuration().await?.member_policies_enabled,
                "Update the VPS"
            );
            let policy: MemberPolicy = serde_json::from_value(input["policy"].clone())?;
            policy.validate().map_err(anyhow::Error::msg)?;
            encode(
                client
                    .update_member_policy(text(input, "member_id")?.parse()?, &policy)
                    .await?,
            )
        }
        "revoke_member_devices" => {
            confirmed(input)?;
            ensure!(
                client.configuration().await?.member_lifecycle_enabled,
                "Update the VPS"
            );
            encode(
                client
                    .revoke_member_devices(text(input, "member_id")?.parse()?, true)
                    .await?,
            )
        }
        "transfer_ownership" => {
            confirmed(input)?;
            ensure!(
                client.status().await?.caller_role == Some(ServerRole::Owner),
                "Only owner may transfer ownership"
            );
            ensure!(
                client.configuration().await?.ownership_transfer_enabled,
                "Update the VPS"
            );
            let result = client
                .transfer_ownership(text(input, "destination_device_id")?.parse()?)
                .await?;
            let mut updated = profile.clone();
            updated.role = ServerRole::Member;
            updated.administrator = true;
            runtime.paths.profile_store().upsert(updated)?;
            encode(result)
        }
        "create_invitation" => {
            let configuration = client.configuration().await?;
            let status = client.status().await?;
            let mut profile = profile.clone();
            if let Some(role) = status.caller_role {
                profile.role = role;
                profile.administrator = status.caller_administrator;
            }
            let recipient = input["recipient_names"].as_bool().unwrap_or(false);
            let admin = input["administrator"].as_bool().unwrap_or(false);
            let max_uses: u16 = serde_json::from_value(
                input
                    .get("max_uses")
                    .filter(|v| !v.is_null())
                    .cloned()
                    .unwrap_or(json!(1)),
            )?;
            let policy: MemberPolicy =
                serde_json::from_value(input.get("member_policy").cloned().unwrap_or(json!({})))?;
            ensure!(
                !recipient || configuration.recipient_names_enabled,
                "Update VPS for recipient names"
            );
            ensure!(
                max_uses == 1
                    && policy.is_default()
                    && (profile.role == ServerRole::Owner || profile.administrator)
                    || configuration.reusable_invitations_enabled,
                "Update VPS for delegated/reusable invitations"
            );
            let mut target = InvitationTarget {
                administrator: admin,
                ..Default::default()
            };
            let mut member_name = if recipient {
                "Invited member".to_owned()
            } else {
                text(input, "member_name")?.to_owned()
            };
            if let Some(id) = input["target_member_id"].as_str() {
                let id: MemberId = id.parse()?;
                let member = client
                    .membership()
                    .await?
                    .members
                    .into_iter()
                    .find(|m| m.id == id)
                    .context("Member no longer exists")?;
                member_name = member.name;
                target = InvitationTarget {
                    member_id: Some(id),
                    role: Some(member.role),
                    administrator: member.administrator,
                };
            }
            ensure!(
                !admin && target.member_id.is_none() || configuration.advanced_invitations_enabled,
                "Update VPS for additional device/Admin invitations"
            );
            let draft = InvitationDraft::new_for_target(
                &profile,
                &member_name,
                if recipient {
                    "New device"
                } else {
                    text(input, "device_name")?
                },
                serde_json::from_value(input["expires_in_seconds"].clone())?,
                target,
            )?
            .with_recipient_names(recipient)
            .with_policy(max_uses, policy)?;
            let response = client.create_invitation(draft.request()).await?;
            let code = draft.finish(response)?;
            let qr = qr_modules(code.qr_payload()).ok();
            Ok(
                json!({"invitation_id":code.invitation_id(),"expires_at_unix":code.expires_at_unix(),"code":code.expose(),"qr_svg":"","qr_modules":qr}),
            )
        }
        _ => bail!("Android command is not implemented"),
    }
}

pub(super) fn qr_modules(value: &str) -> Result<Vec<String>> {
    let code = qrcode::QrCode::with_error_correction_level(value.as_bytes(), qrcode::EcLevel::L)?;
    Ok((0..code.width())
        .map(|y| {
            (0..code.width())
                .map(|x| {
                    if code[(x, y)] == qrcode::Color::Dark {
                        '1'
                    } else {
                        '0'
                    }
                })
                .collect()
        })
        .collect())
}
