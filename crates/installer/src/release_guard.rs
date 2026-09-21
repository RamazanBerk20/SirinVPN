//! Bind maintenance to the inspected root state and preserve the exact active
//! signed artifact when an older desktop performs a configuration repair.
use super::*;
use sirinvpn_release::{ArtifactKind, parse_installed_release_receipt};

const RELEASE_DIRECTORY: &str = "/var/lib/sirinvpn-server-release";
const EXECUTION_DIRECTORY: &str = "/usr/local/lib";

pub(super) struct PreparedArtifact {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub state_guard: String,
    pub preserves_signed_release: bool,
}

pub(super) fn prepare(
    session: &Session,
    request: &InstallRequest,
    discovery: &ServerDiscovery,
) -> Result<PreparedArtifact, InstallerError> {
    let receipt = read_optional_record(session, &request.target, "receipt.json", 768 * 1024)?;
    let trust = read_optional_record(session, &request.target, "trust.json", 160 * 1024)?;
    prepare_from_records(&request.server_binary, discovery, receipt, trust, |path| {
        read_protected_file(session, &request.target, path, MAX_ARTIFACT_SIZE as usize)
    })
}

fn prepare_from_records(
    source: &ServerBinarySource,
    discovery: &ServerDiscovery,
    receipt: Option<Vec<u8>>,
    trust: Option<Vec<u8>>,
    read_cached: impl FnOnce(&str) -> Result<Vec<u8>, InstallerError>,
) -> Result<PreparedArtifact, InstallerError> {
    let state_guard = format!(
        "{}\n{}",
        record_guard("receipt.json", receipt.as_deref()),
        record_guard("trust.json", trust.as_deref())
    );
    let (bytes, sha256, preserves_signed_release) = match (source, receipt) {
        (ServerBinarySource::Signed(_), Some(_)) => {
            return Err(InstallerError::InvalidInput(
                "this VPS already has a signed baseline; use its signed update transaction"
                    .to_owned(),
            ));
        }
        (ServerBinarySource::Signed(bundle), None) => {
            bundle.verify_installed_trust(trust.as_deref())?;
            let (bytes, sha256) = bundle.bytes_for(&discovery.architecture)?;
            (bytes, sha256, false)
        }
        (_, Some(receipt)) => {
            let installed = parse_installed_release_receipt(&receipt).map_err(|error| {
                phase_error("installed VPS release verification", anyhow!(error))
            })?;
            let artifact = installed.active_artifact;
            if artifact.kind != ArtifactKind::ServerElf
                || artifact.target != release_target(&discovery.architecture)?
                || artifact.size_bytes > MAX_ARTIFACT_SIZE
            {
                return Err(InstallerError::Incompatible(
                    "the installed VPS release has an unsupported target".to_owned(),
                ));
            }
            // The root receipt authenticates this already committed release,
            // including when its old key was later revoked for new installs.
            let path = format!("{RELEASE_DIRECTORY}/packages/{}.server", artifact.sha256);
            let bytes = read_cached(&path)?;
            if bytes.len() as u64 != artifact.size_bytes
                || hex::encode(Sha256::digest(&bytes)) != artifact.sha256
                || elf_architecture(&bytes) != Some(discovery.architecture.as_str())
            {
                return Err(InstallerError::InvalidInput(
                    "the committed VPS release cache is damaged; repair cannot substitute a different server version".to_owned()));
            }
            (bytes, artifact.sha256, true)
        }
        (_, None) => {
            if trust.is_some() {
                return Err(InstallerError::InvalidInput(
                    "this VPS has a signing policy without a registered baseline; install a verified signed baseline before repairing its executable".to_owned()));
            }
            let (bytes, sha256) = load_install_server_artifact(source, discovery)?;
            (bytes, sha256, false)
        }
    };
    Ok(PreparedArtifact {
        bytes,
        sha256,
        state_guard,
        preserves_signed_release,
    })
}

fn read_optional_record(
    session: &Session,
    target: &SshTarget,
    name: &str,
    maximum: usize,
) -> Result<Option<Vec<u8>>, InstallerError> {
    let path = format!("{RELEASE_DIRECTORY}/{name}");
    let command = optional_record_command(&path, maximum);
    let bytes = run_privileged_bytes(session, target, &command, maximum + 1)
        .map_err(|error| phase_error("VPS release state inspection", error))?;
    decode_optional_record(&bytes)
        .map_err(|error| phase_error("VPS release state inspection", error))
}

fn optional_record_command(path: &str, maximum: usize) -> String {
    let quoted = shell_quote(path);
    // The SSH binary reader deliberately rejects empty replies. A fresh VPS
    // has no release records, so encode absence explicitly without relaxing
    // the protections used for required artifacts or existing empty records.
    format!(
        "set -eu\nexport LC_ALL=C\nif [ -e {quoted} ] || [ -L {quoted} ]; then\nprintf '\\001'\n{}\nelse\nprintf '\\000'\nfi",
        protected_read_command(path, maximum)
    )
}

fn decode_optional_record(bytes: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
    match bytes {
        [0] => Ok(None),
        [1, record @ ..] if !record.is_empty() => Ok(Some(record.to_vec())),
        _ => bail!("remote release record returned an invalid presence marker"),
    }
}

fn read_protected_file(
    session: &Session,
    target: &SshTarget,
    path: &str,
    maximum: usize,
) -> Result<Vec<u8>, InstallerError> {
    run_privileged_bytes(
        session,
        target,
        &format!("set -eu\n{}", protected_read_command(path, maximum)),
        maximum,
    )
    .map(|bytes| bytes.to_vec())
    .map_err(|error| phase_error("committed VPS artifact read", error))
}

fn protected_read_command(path: &str, maximum: usize) -> String {
    let quoted = shell_quote(path);
    format!(
        r#"{permissions}
[ "$(stat -c %s {quoted})" -gt 0 ]
[ "$(stat -c %s {quoted})" -le {maximum} ]
head -c {maximum} -- {quoted}"#,
        permissions = protected_file_guard(path)
    )
}

fn protected_file_guard(path: &str) -> String {
    let quoted = shell_quote(path);
    let parent = shell_quote(
        Path::new(path)
            .parent()
            .expect("fixed absolute release path")
            .to_str()
            .expect("fixed UTF-8 path"),
    );
    format!(
        r#"[ ! -L '{RELEASE_DIRECTORY}' ]
[ -d '{RELEASE_DIRECTORY}' ] && [ "$(stat -c '%u:%a' '{RELEASE_DIRECTORY}')" = '0:700' ]
[ ! -L {parent} ] && [ -d {parent} ] && [ "$(stat -c '%u:%a' {parent})" = '0:700' ]
[ ! -L {quoted} ] && [ -f {quoted} ]
[ "$(stat -c '%u:%a:%h' {quoted})" = '0:600:1' ]"#
    )
}

fn record_guard(name: &str, bytes: Option<&[u8]>) -> String {
    let path = format!("{RELEASE_DIRECTORY}/{name}");
    let quoted = shell_quote(&path);
    match bytes {
        None => format!(
            "[ ! -e {quoted} ] && [ ! -L {quoted} ] || {{ echo 'VPS release state changed; review it again' >&2; exit 1; }}"
        ),
        Some(bytes) => format!(
            r#"{permissions}
[ "$(sha256sum -- {quoted} | cut -d' ' -f1)" = '{digest}' ] || {{ echo 'VPS release state changed; review it again' >&2; exit 1; }}"#,
            permissions = protected_file_guard(&path),
            digest = hex::encode(Sha256::digest(bytes))
        ),
    }
}

impl PreparedArtifact {
    pub fn save_committed_binary(&self) -> &'static str {
        if self.preserves_signed_release {
            "install -o root -g root -m 0600 \"$STAGED_BINARY\" \"$BACKUP_DIR/committed.server.preparing\"\nsync -f \"$BACKUP_DIR/committed.server.preparing\"\nmv \"$BACKUP_DIR/committed.server.preparing\" \"$BACKUP_DIR/committed.server\"\nsync -f \"$BACKUP_DIR\""
        } else {
            ""
        }
    }
    pub fn restore_committed_binary(&self) -> String {
        if self.preserves_signed_release {
            format!(
                r#"if [ -f "$BACKUP_DIR/committed.server" ]; then
  [ "$(sha256sum "$BACKUP_DIR/committed.server" | cut -d' ' -f1)" = '{}' ]
  install -o root -g root -m 0755 "$BACKUP_DIR/committed.server" /usr/local/lib/sirinvpn/sirinvpn-server
  install -o root -g root -m 0755 "$BACKUP_DIR/committed.server" /usr/local/lib/sirinvpn/sirinvpn-updater
  sync -f /usr/local/lib/sirinvpn
fi"#,
                self.sha256
            )
        } else {
            String::new()
        }
    }
    pub fn root_preflight(&self, remote_binary: &str, nonce: &str, repair: bool) -> String {
        let compatibility = if repair {
            // Capabilities contain public fixed schema numbers. Require the
            // handoff guard before executing any state-writing command.
            r#""$STAGED_BINARY" release capabilities >"$STAGING_DIR/capabilities.json"
grep -Eq '"server_handoff_guard"[[:space:]]*:[[:space:]]*1[[:space:]]*[,}]' "$STAGING_DIR/capabilities.json" || { echo 'The repair binary cannot preserve the endpoint handoff firewall guard' >&2; exit 1; }
grep -Eq '"server_maintenance_guard"[[:space:]]*:[[:space:]]*1[[:space:]]*[,}]' "$STAGING_DIR/capabilities.json" || { echo 'The server release cannot protect persistent maintenance; install a compatible signed release first' >&2; exit 1; }
"$STAGED_BINARY" --state-directory /etc/sirinvpn validate-state"#
        } else {
            ""
        };
        format!(
            r#"{state_guard}
# /run can be mounted noexec. Stage on the server installation filesystem,
# inside a fresh root-private directory under a protected executable parent.
[ ! -L '{execution_directory}' ]
[ -n "$(find '{execution_directory}' -maxdepth 0 -type d -uid 0 ! -perm /022 -print)" ]
STAGING_DIR=$(mktemp -d '{execution_directory}/.sirinvpn-stage-{nonce}.XXXXXX')
trap 'rm -rf -- "$STAGING_DIR"' EXIT
STAGED_BINARY="$STAGING_DIR/sirinvpn-server"
install -o root -g root -m 0700 {source} "$STAGED_BINARY"
[ "$(sha256sum "$STAGED_BINARY" | cut -d' ' -f1)" = '{sha256}' ] || {{ echo 'The staged server artifact changed' >&2; exit 1; }}
{compatibility}"#,
            state_guard = self.state_guard,
            execution_directory = EXECUTION_DIRECTORY,
            source = shell_quote(remote_binary),
            sha256 = self.sha256
        )
    }
}

#[cfg(test)]
mod tests;
