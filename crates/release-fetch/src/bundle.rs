use super::*;
use std::io::Read;

/// Files are bounded and verified again when reopening a fetched bundle. Callers
/// must rehash artifact bytes after copying from a writable staging directory.
pub struct VerifiedReleaseBundle {
    pub manifest_bytes: Vec<u8>,
    pub signature_bytes: Vec<u8>,
    pub trust_policy_bytes: Vec<u8>,
    pub trust_signature_bytes: Vec<u8>,
    pub verified: sirinvpn_release::VerifiedArtifactRelease,
    pub artifact_directory: PathBuf,
}

impl VerifiedReleaseBundle {
    pub fn open(directory: &Path, kind: ArtifactKind, target: &str) -> Result<Self, FetchError> {
        let manifest_bytes =
            read_bounded(directory, RELEASE_MANIFEST_FILE_NAME, MAX_MANIFEST_BYTES)?;
        let signature_bytes =
            read_bounded(directory, RELEASE_SIGNATURE_FILE_NAME, MAX_SIGNATURE_BYTES)?;
        let trust_policy_bytes =
            read_bounded(directory, TRUST_POLICY_FILE_NAME, MAX_TRUST_POLICY_BYTES)?;
        let trust_signature_bytes = read_bounded(
            directory,
            TRUST_SIGNATURE_FILE_NAME,
            MAX_TRUST_SIGNATURE_BYTES,
        )?;
        let trust = verify_trust_policy(
            &trust_policy_bytes,
            &trust_signature_bytes,
            BUNDLED_RELEASE_TRUST_ROOT_PEM,
        )?;
        let artifact_directory = directory.join(ARTIFACT_DIRECTORY_NAME);
        if !fs::symlink_metadata(&artifact_directory)?
            .file_type()
            .is_dir()
        {
            return Err(FetchError::InvalidDestination);
        }
        let verified = verify_release_artifact_with_trust_policy(
            &manifest_bytes,
            &signature_bytes,
            &trust,
            &artifact_directory,
            kind,
            target,
        )?;
        Ok(Self {
            manifest_bytes,
            signature_bytes,
            trust_policy_bytes,
            trust_signature_bytes,
            verified,
            artifact_directory,
        })
    }

    pub fn server_bundle(&self) -> sirinvpn_release::ServerReleaseBundle<'_> {
        sirinvpn_release::ServerReleaseBundle {
            manifest: &self.manifest_bytes,
            signature: &self.signature_bytes,
            artifact_directory: &self.artifact_directory,
            target: &self.verified.artifact.target,
        }
    }
}

fn read_bounded(directory: &Path, name: &str, maximum: u64) -> Result<Vec<u8>, FetchError> {
    if !fs::symlink_metadata(directory)?.file_type().is_dir() {
        return Err(FetchError::InvalidDestination);
    }
    let file = sirinvpn_platform::files::open_no_follow(&directory.join(name))?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(FetchError::ResponseTooLarge {
            resource: name.to_owned(),
            maximum_bytes: maximum,
        });
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(FetchError::ResponseTooLarge {
            resource: name.to_owned(),
            maximum_bytes: maximum,
        });
    }
    Ok(bytes)
}
