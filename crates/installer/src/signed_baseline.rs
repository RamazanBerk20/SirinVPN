use super::*;
use sirinvpn_release::{ArtifactKind, ReleaseArtifact};
use sirinvpn_release_fetch::{
    RELEASE_MANIFEST_FILE_NAME, RELEASE_SIGNATURE_FILE_NAME, TRUST_POLICY_FILE_NAME,
    TRUST_SIGNATURE_FILE_NAME, VerifiedReleaseBundle,
};
use std::sync::Arc;

/// Immutable authenticated bytes prevent a source path from changing between
/// signature verification and the SSH installer's upload.
pub struct SignedServerBundle {
    artifact: Arc<[u8]>,
    architecture: String,
    manifest: Vec<u8>,
    signature: Vec<u8>,
    trust_policy: Vec<u8>,
    trust_signature: Vec<u8>,
    summary: SignedBaselineCandidate,
}
impl std::fmt::Debug for SignedServerBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedServerBundle")
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct SignedBaselineCandidate {
    pub release_version: String,
    pub release_sequence: String,
    pub channel: String,
    pub security_update: bool,
    pub manifest_sha256: String,
    pub artifact: ReleaseArtifact,
}

impl SignedServerBundle {
    pub fn open(directory: &Path, architecture: &str) -> Result<Self, InstallerError> {
        let bundle = VerifiedReleaseBundle::open(
            directory,
            ArtifactKind::ServerElf,
            release_target(architecture)?,
        )
        .map_err(|error| phase_error("signed baseline verification", anyhow!(error)))?;
        for name in [
            "server_release_transaction",
            "server_handoff_guard",
            "server_maintenance_guard",
            "server_security_update_policy",
        ] {
            if !bundle
                .verified
                .manifest
                .state_compatibility
                .iter()
                .any(|state| {
                    state.state == name && state.reads.minimum <= 1 && state.reads.maximum >= 1
                })
            {
                return Err(InstallerError::Incompatible(format!(
                    "the signed baseline does not support {name}"
                )));
            }
        }
        let path = bundle
            .artifact_directory
            .join(&bundle.verified.artifact.file_name);
        let mut bytes = Vec::new();
        fs::File::open(path)
            .and_then(|file| file.take(MAX_ARTIFACT_SIZE + 1).read_to_end(&mut bytes))
            .map_err(|error| phase_error("signed baseline bytes", anyhow!(error)))?;
        if bytes.len() as u64 != bundle.verified.artifact.size_bytes
            || bytes.len() as u64 > MAX_ARTIFACT_SIZE
            || elf_architecture(&bytes) != Some(architecture)
            || hex::encode(Sha256::digest(&bytes)) != bundle.verified.artifact.sha256
        {
            return Err(InstallerError::InvalidInput(
                "the verified server artifact changed or has an unsupported ELF architecture"
                    .to_owned(),
            ));
        }
        let manifest = &bundle.verified.manifest;
        let summary = SignedBaselineCandidate {
            release_version: manifest.release_version.clone(),
            release_sequence: manifest.release_sequence.to_string(),
            channel: manifest.channel.to_string(),
            security_update: manifest.security_update,
            manifest_sha256: bundle.verified.manifest_sha256,
            artifact: bundle.verified.artifact,
        };
        Ok(Self {
            artifact: bytes.into(),
            architecture: architecture.to_owned(),
            manifest: bundle.manifest_bytes,
            signature: bundle.signature_bytes,
            trust_policy: bundle.trust_policy_bytes,
            trust_signature: bundle.trust_signature_bytes,
            summary,
        })
    }
    pub fn summary(&self) -> &SignedBaselineCandidate {
        &self.summary
    }
    pub(super) fn verify_installed_trust(
        &self,
        installed: Option<&[u8]>,
    ) -> Result<(), InstallerError> {
        let trust = sirinvpn_release::verify_trust_policy_update(
            installed,
            &self.trust_policy,
            &self.trust_signature,
        )
        .map_err(|error| phase_error("VPS signing policy verification", anyhow!(error)))?;
        sirinvpn_release::verify_manifest_with_trust_policy(
            &self.manifest,
            &self.signature,
            &trust,
        )
        .map_err(|error| phase_error("VPS release key verification", anyhow!(error)))?;
        Ok(())
    }
    pub(super) fn bytes_for(
        &self,
        architecture: &str,
    ) -> Result<(Vec<u8>, String), InstallerError> {
        if architecture != self.architecture {
            return Err(InstallerError::Incompatible(
                "the signed bundle targets a different VPS architecture".to_owned(),
            ));
        }
        Ok((self.artifact.to_vec(), self.summary.artifact.sha256.clone()))
    }
    fn upload(&self, session: &Session, directory: &str) -> Result<(), InstallerError> {
        run(
            session,
            &format!(
                "umask 077; install -d -m 0700 {}",
                shell_quote(&format!("{directory}/artifact"))
            ),
        )
        .map_err(|error| phase_error("signed baseline staging", error))?;
        for (name, bytes) in [
            (RELEASE_MANIFEST_FILE_NAME, &self.manifest),
            (RELEASE_SIGNATURE_FILE_NAME, &self.signature),
            (TRUST_POLICY_FILE_NAME, &self.trust_policy),
            (TRUST_SIGNATURE_FILE_NAME, &self.trust_signature),
        ] {
            upload(session, &Path::new(directory).join(name), bytes, 0o600)
                .map_err(|error| phase_error("signed baseline metadata upload", error))?;
        }
        upload(
            session,
            &Path::new(directory)
                .join("artifact")
                .join(&self.summary.artifact.file_name),
            &self.artifact,
            0o600,
        )
        .map_err(|error| phase_error("signed baseline artifact upload", error))?;
        Ok(())
    }
}

pub struct SignedBaselineOutcome {
    pub repair: RepairOutcome,
    pub release: serde_json::Value,
}

impl RepairOutcome {
    pub fn updated_profile(&self, current: &ServerProfile) -> ServerProfile {
        let mut profile = current.clone();
        profile.endpoint = self.endpoint.clone();
        profile.endpoint_generation = self.endpoint_generation;
        profile.alternate_endpoint_hosts = self.alternate_endpoint_hosts.clone();
        profile.endpoint_discovery_port = self.endpoint_discovery_port;
        profile.pending_previous_endpoint = None;
        profile.pending_previous_transports = None;
        profile.ipv6_tunnel_enabled = self.ipv6_tunnel_enabled;
        profile.obfuscated_udp = self.obfuscated_udp.clone();
        profile.tcp_fallback = self.tcp_fallback.clone();
        profile.tls_like = self.tls_like.clone();
        profile
    }
}
impl Provisioner {
    pub fn inspect_signed_baseline_target(
        request: &ServerReleaseRequest,
    ) -> Result<ServerDiscovery, InstallerError> {
        validate_owner_operation_request(
            &request.profile,
            &request.target,
            &request.identity,
            "signed VPS baseline installation",
        )?;
        let session = verified_session(request)?;
        let discovery = discover(&session)?;
        check_compatibility(&discovery)?;
        let absent = run_privileged(&session, &request.target,
            "if [ -e /var/lib/sirinvpn-server-release/receipt.json ]; then printf 'present'; else printf 'absent'; fi")
            .map_err(|error| phase_error("signed baseline state inspection", error))?;
        if absent.trim() != "absent" {
            return Err(InstallerError::InvalidInput(
                "this VPS already has a signed baseline; use the normal signed update transaction"
                    .to_owned(),
            ));
        }
        Ok(discovery)
    }
    pub fn install_signed_baseline(
        request: ServerReleaseRequest,
        bundle: Arc<SignedServerBundle>,
    ) -> Result<SignedBaselineOutcome, InstallerError> {
        let discovery = Self::inspect_signed_baseline_target(&request)?;
        bundle.bytes_for(&discovery.architecture)?;
        let repair = Self::repair(RepairRequest {
            profile: request.profile.clone(),
            target: request.target.clone(),
            server_binary: ServerBinarySource::Signed(bundle.clone()),
            identity: request.identity.clone(),
            dns_upstream: None,
            private_dns_records: None,
            transport: None,
        })?;
        let session = verified_session(&request)?;
        let directory = format!("/tmp/sirinvpn-signed-baseline-{}", Uuid::new_v4().simple());
        run(
            &session,
            &format!("umask 077; install -d -m 0700 {}", shell_quote(&directory)),
        )
        .map_err(|error| phase_error("signed baseline registration staging", error))?;
        let result = (|| {
            bundle.upload(&session, &directory)?;
            let output = run_privileged(
                &session,
                &request.target,
                &format!(
                    "/usr/local/lib/sirinvpn/sirinvpn-updater release adopt --bundle {} || true",
                    shell_quote(&directory)
                ),
            )
            .map_err(|error| phase_error("signed baseline registration", error))?;
            super::release_update::parse_response(&output)
        })();
        let _ = run(&session, &format!("rm -rf -- {}", shell_quote(&directory)));
        let release = result.map_err(|_| InstallerError::InvalidInput(
            "the verified server build was installed, but its signed baseline could not be registered; check the matching release and register its baseline before updating".to_owned()))?;
        Ok(SignedBaselineOutcome { repair, release })
    }
}

fn verified_session(request: &ServerReleaseRequest) -> Result<Session, InstallerError> {
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
    Ok(session)
}

pub fn release_target(architecture: &str) -> Result<&'static str, InstallerError> {
    match architecture {
        "x86_64" => Ok("x86_64-unknown-linux-gnu"),
        "aarch64" => Ok("aarch64-unknown-linux-gnu"),
        _ => Err(InstallerError::Incompatible(
            "this VPS architecture has no supported signed server release".to_owned(),
        )),
    }
}
