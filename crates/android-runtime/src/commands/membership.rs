use super::*;
use sirinvpn_core::{InvitationDraft, InvitationTarget, ManagementError};

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
        "rename_member" => {
            let member_id: MemberId = text(input, "member_id")?.parse()?;
            let name = text(input, "name")?;
            ensure!(
                validate_server_name(name).is_ok(),
                "Enter a name with 1 to 64 visible characters."
            );
            ensure!(
                client.configuration().await?.person_rename_enabled,
                "Update this server to rename people."
            );
            match client.rename_member(member_id, name.to_owned()).await {
                Err(
                    error @ ManagementError::RequestRejected {
                        code: ErrorCode::ConflictDetected,
                        ..
                    },
                ) => {
                    // A conflict has other causes too; only this person's outstanding codes mean this.
                    let has_codes = !super::rules::person_name_taken(&error)
                        && client.membership().await.is_ok_and(|snapshot| {
                            snapshot
                                .active_invitations
                                .iter()
                                .any(|invitation| invitation.target_member_id == Some(member_id))
                        });
                    Err(if has_codes {
                        super::rules::refused("person_has_join_codes", error).into()
                    } else {
                        error.into()
                    })
                }
                result => encode(result?),
            }
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
        "update_device_subnet_routes" => {
            ensure!(
                client.configuration().await?.subnet_routes_enabled,
                "Server needs an update"
            );
            let routes: Vec<String> =
                serde_json::from_value(input["routes"].clone()).context("Invalid subnet routes")?;
            encode(
                client
                    .update_device_subnet_routes(text(input, "device_id")?.parse()?, routes)
                    .await?,
            )
        }
        "set_device_pair" => {
            ensure!(
                client.configuration().await?.device_pairs_enabled,
                "Server needs an update"
            );
            let pair: DevicePair = serde_json::from_value(json!({
                "device_id": input["device_id"],
                "peer_device_id": input["peer_device_id"],
                "one_way": input["one_way"].as_bool().unwrap_or(false),
            }))
            .context("Invalid device pair")?;
            encode(client.set_device_pair(&pair).await?)
        }
        "remove_device_pair" => encode(
            client
                .remove_device_pair(
                    text(input, "device_id")?.parse()?,
                    text(input, "peer_device_id")?.parse()?,
                )
                .await?,
        ),
        "create_port_forward" => {
            confirmed(input)?;
            ensure!(
                client.configuration().await?.port_forwarding_enabled,
                "Server needs repair"
            );
            let request: PortForwardCreateRequest = serde_json::from_value(
                json!({"protocol":input["protocol"],"public_port":input["public_port"],"device_id":input["device_id"],"device_port":input["device_port"]}),
            )?;
            ensure!(
                request.device_port != 0,
                "Enter a device port from 1 to 65535."
            );
            match client.create_port_forward(&request).await {
                // The device port is checked above, so the VPS refused the public port.
                Err(
                    error @ ManagementError::RequestRejected {
                        code: ErrorCode::InvalidInput,
                        ..
                    },
                ) => Err(super::rules::refused("port_forward_public_port", error).into()),
                result => encode(result?),
            }
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
            runtime
                .paths
                .profile_store()
                .update(profile.id, |current| {
                    super::rules::demote_after_transfer(current);
                    Ok(())
                })?;
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
            let fixed = input["fixed_member_name"].as_bool().unwrap_or(false);
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
                !fixed
                    || (recipient && max_uses == 1 && input["target_member_id"].as_str().is_none()),
                "A join code that names the person is for one new person and one use."
            );
            ensure!(
                !fixed || configuration.named_join_codes_enabled,
                "Update this server to create join codes that name the person."
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
            let mut member_name = if recipient && !fixed {
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
            .with_policy(max_uses, policy)?
            .with_fixed_member_name(fixed)?;
            let response = client.create_invitation_body(&draft.body()).await?;
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
