use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServerReleaseAction {
    Status,
    Check {
        source: String,
        channel: String,
    },
    Install {
        manifest_sha256: String,
    },
    Rollback {
        confirmed: bool,
    },
    Configure {
        enabled: bool,
        source: Option<String>,
    },
    Recover,
}

pub struct ServerReleaseRequest {
    pub profile: ServerProfile,
    pub target: SshTarget,
    pub identity: PublicIdentity,
    pub action: ServerReleaseAction,
}

impl Provisioner {
    pub fn manage_server_release(
        request: ServerReleaseRequest,
    ) -> Result<serde_json::Value, InstallerError> {
        validate_owner_operation_request(
            &request.profile,
            &request.target,
            &request.identity,
            "signed VPS release management",
        )?;
        let arguments = action_arguments(&request.action)?;
        let session =
            connect_transport(&request.target).map_err(|error| phase_error("connection", error))?;
        verify_host_key(&session, request.target.expected_host_key_sha256.as_deref())?;
        authenticate(&session, &request.target)?;
        verify_repair_target(
            &session,
            &request.target,
            &request.profile,
            &request.identity,
            OwnerPreflightOperation::Release,
        )?;
        // The command emits bounded functional JSON even on a rejected update.
        // Never forward SSH stderr, which can contain authentication material.
        let command = format!(
            "if [ -x /usr/local/lib/sirinvpn/sirinvpn-updater ]; then /usr/local/lib/sirinvpn/sirinvpn-updater release {arguments} || true; else printf '%s\\n' '{{\"error\":\"Repair the VPS components once to install the signed release coordinator.\"}}'; fi"
        );
        session.set_timeout(20 * 60 * 1000);
        let output = run_privileged(&session, &request.target, &command)
            .map_err(|error| phase_error("VPS release operation", error))?;
        parse_response(&output)
    }
}

pub(super) fn parse_response(output: &str) -> Result<serde_json::Value, InstallerError> {
    if output.len() > 64 * 1024 {
        return Err(InstallerError::InvalidInput(
            "the VPS release response is oversized".to_owned(),
        ));
    }
    let value: serde_json::Value = serde_json::from_str(output.trim()).map_err(|_| {
        InstallerError::InvalidInput(
            "the VPS release coordinator returned an invalid response".to_owned(),
        )
    })?;
    if let Some(error) = value.get("error").and_then(serde_json::Value::as_str) {
        if error.len() > 2048 {
            return Err(InstallerError::InvalidInput(
                "the VPS rejected the release operation".to_owned(),
            ));
        }
        return Err(phase_error("VPS release operation", anyhow!("{error}")));
    }
    Ok(value)
}

fn action_arguments(action: &ServerReleaseAction) -> Result<String, InstallerError> {
    Ok(match action {
        ServerReleaseAction::Status => "status".to_owned(),
        ServerReleaseAction::Check { source, channel } => {
            validate_source(source)?;
            if !matches!(channel.as_str(), "stable" | "preview") {
                return Err(InstallerError::InvalidInput(
                    "choose the stable or preview release channel".to_owned(),
                ));
            }
            format!(
                "check --source {} --channel {}",
                shell_quote(source),
                shell_quote(channel)
            )
        }
        ServerReleaseAction::Install { manifest_sha256 } => {
            if manifest_sha256.len() != 64
                || !manifest_sha256
                    .bytes()
                    .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
            {
                return Err(InstallerError::InvalidInput(
                    "check a signed release before installing it".to_owned(),
                ));
            }
            format!("install --manifest-sha256 {}", shell_quote(manifest_sha256))
        }
        ServerReleaseAction::Rollback { confirmed } => {
            if !confirmed {
                return Err(InstallerError::InvalidInput(
                    "confirm rollback to the previous signed release".to_owned(),
                ));
            }
            "rollback --confirmed".to_owned()
        }
        ServerReleaseAction::Configure { enabled, source } => {
            if *enabled && source.is_none() {
                return Err(InstallerError::InvalidInput(
                    "choose an HTTPS release source".to_owned(),
                ));
            }
            let mut arguments = "configure".to_owned();
            if *enabled {
                arguments.push_str(" --enabled");
            }
            if let Some(source) = source {
                validate_source(source)?;
                arguments.push_str(&format!(" --source {}", shell_quote(source)));
            }
            arguments
        }
        ServerReleaseAction::Recover => "recover".to_owned(),
    })
}

fn validate_source(source: &str) -> Result<(), InstallerError> {
    sirinvpn_release_fetch::validate_source_url(source)
        .map_err(|error| InstallerError::InvalidInput(error.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests;
