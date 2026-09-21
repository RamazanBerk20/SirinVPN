use super::*;

const POLICY: &str = "security-policy.json";
const OUTCOME: &str = "security-outcome.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityUpdatePolicy {
    pub schema_version: u16,
    pub enabled: bool,
    pub source: Option<String>,
    pub channel: ReleaseChannel,
}
impl Default for SecurityUpdatePolicy {
    fn default() -> Self {
        Self {
            schema_version: 1,
            enabled: false,
            source: None,
            channel: ReleaseChannel::Stable,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomaticUpdateOutcome {
    Disabled,
    BaselineRequired,
    NoNewSecurityRelease,
    Installed,
    Failed,
}

pub fn load() -> anyhow::Result<SecurityUpdatePolicy> {
    let policy = files::read_record(POLICY)?.unwrap_or_default();
    validate(&policy)?;
    Ok(policy)
}

fn validate(policy: &SecurityUpdatePolicy) -> anyhow::Result<()> {
    anyhow::ensure!(
        policy.schema_version == 1 && policy.channel == ReleaseChannel::Stable,
        "automatic VPS security updates require policy schema 1 and the stable channel"
    );
    anyhow::ensure!(
        !policy.enabled || policy.source.is_some(),
        "choose an HTTPS release source before enabling automatic updates"
    );
    if let Some(source) = &policy.source {
        sirinvpn_release_fetch::validate_source_url(source)?;
    }
    Ok(())
}

pub fn configure(enabled: bool, source: Option<String>) -> anyhow::Result<SecurityUpdatePolicy> {
    let policy = SecurityUpdatePolicy {
        enabled,
        source,
        ..SecurityUpdatePolicy::default()
    };
    validate(&policy)?;
    let previous = load()?;
    files::write_record(POLICY, &policy)?;
    let action = if enabled { "enable" } else { "disable" };
    if let Err(error) = host::systemctl(&[action, "--now", "sirinvpn-security-update.timer"]) {
        files::write_record(POLICY, &previous)?;
        let restore = if previous.enabled {
            "enable"
        } else {
            "disable"
        };
        let _ = host::systemctl(&[restore, "--now", "sirinvpn-security-update.timer"]);
        return Err(error.into());
    }
    Ok(policy)
}

pub fn latest() -> anyhow::Result<Option<AutomaticUpdateOutcome>> {
    files::read_record(OUTCOME)
}

pub fn automatic(host: &host::SystemServerHost) -> anyhow::Result<AutomaticUpdateOutcome> {
    let result = automatic_inner(host);
    let outcome = match &result {
        Ok(value) => *value,
        Err(_) => AutomaticUpdateOutcome::Failed,
    };
    files::write_record(OUTCOME, &outcome)?;
    result
}

fn automatic_inner(host: &host::SystemServerHost) -> anyhow::Result<AutomaticUpdateOutcome> {
    let policy = load()?;
    if !policy.enabled {
        return Ok(AutomaticUpdateOutcome::Disabled);
    }
    let Some(installed) = store().inspect()? else {
        return Ok(AutomaticUpdateOutcome::BaselineRequired);
    };
    let bundle = files::fetch_unprivileged(
        policy
            .source
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("release source is missing"))?,
        policy.channel,
    )?;
    let verified = VerifiedReleaseBundle::open(bundle.path(), ArtifactKind::ServerElf, target()?)?;
    apply_trust(&verified)?;
    // An explicit rollback cannot be immediately undone by the automatic task.
    if !eligible_security_update(&installed, &verified.verified.manifest) {
        return Ok(AutomaticUpdateOutcome::NoNewSecurityRelease);
    }
    store().install_trusted_server(&verified.server_bundle(), host)?;
    Ok(AutomaticUpdateOutcome::Installed)
}

fn eligible_security_update(
    installed: &sirinvpn_release::InstalledReleaseSummary,
    candidate: &sirinvpn_release::ReleaseManifest,
) -> bool {
    candidate.channel == ReleaseChannel::Stable
        && installed.channel == ReleaseChannel::Stable
        && candidate.security_update
        && candidate.release_sequence > installed.highest_accepted_release_sequence
}

#[cfg(test)]
mod tests;
