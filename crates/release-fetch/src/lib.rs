#![forbid(unsafe_code)]

mod bundle;
pub use bundle::VerifiedReleaseBundle;

use reqwest::{
    Client, StatusCode, Url,
    header::{ACCEPT, ACCEPT_ENCODING},
};
use serde::Serialize;
use sirinvpn_release::{
    ArtifactKind, BUNDLED_RELEASE_TRUST_ROOT_PEM, MAX_MANIFEST_BYTES, MAX_SIGNATURE_BYTES,
    MAX_TRUST_POLICY_BYTES, MAX_TRUST_SIGNATURE_BYTES, ReleaseArtifact, ReleaseChannel,
    ReleaseError, verify_manifest_with_trust_policy, verify_release_artifact_with_trust_policy,
    verify_trust_policy,
};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::{Builder as TempBuilder, TempDir};
use thiserror::Error;

pub const RELEASE_MANIFEST_FILE_NAME: &str = "sirinvpn-release.json";
pub const RELEASE_SIGNATURE_FILE_NAME: &str = "sirinvpn-release.sig.json";
pub const TRUST_POLICY_FILE_NAME: &str = "sirinvpn-release-trust.json";
pub const TRUST_SIGNATURE_FILE_NAME: &str = "sirinvpn-release-trust.sig.json";
pub const ARTIFACT_DIRECTORY_NAME: &str = "artifact";

const MAX_SOURCE_URL_BYTES: usize = 2 * 1024;
const MAX_ARTIFACT_TARGET_BYTES: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const USER_AGENT: &str = "SirinVPN-release-fetch/1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseFetchRequest {
    pub source: String,
    pub expected_channel: ReleaseChannel,
    pub artifact_kind: ArtifactKind,
    pub artifact_target: String,
    pub destination: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FetchedRelease {
    pub release_version: String,
    pub release_sequence: u64,
    pub channel: ReleaseChannel,
    pub security_update: bool,
    pub trust_policy_sequence: u64,
    pub root_key_id_sha256: String,
    pub release_key_id_sha256: String,
    pub artifact: ReleaseArtifact,
    pub bundle_directory: PathBuf,
    pub artifact_directory: PathBuf,
}

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("the release source URL is empty, too long, or invalid")]
    InvalidSourceUrl,
    #[error("the release source must use HTTPS")]
    SourceMustUseHttps,
    #[error("the release source must not contain credentials, a query, or a fragment")]
    SourceContainsPrivateData,
    #[error("the release source must be a base directory URL ending in '/'")]
    SourceIsNotDirectory,
    #[error("the requested artifact target is empty or exceeds 256 bytes")]
    InvalidArtifactTarget,
    #[error("the destination must be a normalized absolute path below an existing real directory")]
    InvalidDestination,
    #[error("the destination already exists; refusing to replace it")]
    DestinationExists,
    #[error("could not construct the bounded HTTPS release client")]
    ClientConfiguration(#[source] reqwest::Error),
    #[error("the HTTPS request for {resource} failed")]
    Request {
        resource: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("the release source returned HTTP status {status} for {resource}")]
    HttpStatus { resource: String, status: u16 },
    #[error(
        "the release source returned an encoded response for {0}; only identity encoding is accepted"
    )]
    EncodedResponse(String),
    #[error("the response for {resource} exceeds its {maximum_bytes}-byte limit")]
    ResponseTooLarge {
        resource: String,
        maximum_bytes: u64,
    },
    #[error("the response size for {resource} does not match the signed release manifest")]
    ResponseSizeMismatch { resource: String },
    #[error("the root-authorized release channel is {actual}, not the requested {expected}")]
    ChannelMismatch {
        expected: ReleaseChannel,
        actual: ReleaseChannel,
    },
    #[error(
        "this platform cannot atomically publish a fetched release without replacing an existing path"
    )]
    AtomicCommitUnsupported,
    #[error("the fetched release was committed at {path}, but syncing its parent directory failed")]
    CommitDurability {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("release file operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("release authenticity verification failed: {0}")]
    Release(#[from] ReleaseError),
}

pub async fn fetch_release(request: ReleaseFetchRequest) -> Result<FetchedRelease, FetchError> {
    let client = secure_client_builder()
        .build()
        .map_err(FetchError::ClientConfiguration)?;
    fetch_release_with_client_and_root(request, &client, BUNDLED_RELEASE_TRUST_ROOT_PEM).await
}

fn secure_client_builder() -> reqwest::ClientBuilder {
    Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .referer(false)
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .user_agent(USER_AGENT)
}

async fn fetch_release_with_client_and_root(
    request: ReleaseFetchRequest,
    client: &Client,
    root_public_key_pem: &str,
) -> Result<FetchedRelease, FetchError> {
    let source = validate_source_url(&request.source)?;
    validate_artifact_target(&request.artifact_target)?;
    let destination = validate_destination(&request.destination)?;
    let parent = destination.parent().ok_or(FetchError::InvalidDestination)?;
    let staging = TempBuilder::new()
        .prefix(".sirinvpn-release-fetch.")
        .tempdir_in(parent)?;
    sirinvpn_platform::files::restrict_temporary_directory(&staging)?;

    let policy = fetch_bounded(
        client,
        source_file_url(&source, TRUST_POLICY_FILE_NAME)?,
        TRUST_POLICY_FILE_NAME,
        MAX_TRUST_POLICY_BYTES,
    )
    .await?;
    let trust_signature = fetch_bounded(
        client,
        source_file_url(&source, TRUST_SIGNATURE_FILE_NAME)?,
        TRUST_SIGNATURE_FILE_NAME,
        MAX_TRUST_SIGNATURE_BYTES,
    )
    .await?;
    let trust = verify_trust_policy(&policy, &trust_signature, root_public_key_pem)?;

    let manifest = fetch_bounded(
        client,
        source_file_url(&source, RELEASE_MANIFEST_FILE_NAME)?,
        RELEASE_MANIFEST_FILE_NAME,
        MAX_MANIFEST_BYTES,
    )
    .await?;
    let release_signature = fetch_bounded(
        client,
        source_file_url(&source, RELEASE_SIGNATURE_FILE_NAME)?,
        RELEASE_SIGNATURE_FILE_NAME,
        MAX_SIGNATURE_BYTES,
    )
    .await?;
    let verified_manifest =
        verify_manifest_with_trust_policy(&manifest, &release_signature, &trust)?;
    if verified_manifest.manifest.channel != request.expected_channel {
        return Err(FetchError::ChannelMismatch {
            expected: request.expected_channel,
            actual: verified_manifest.manifest.channel,
        });
    }
    let artifact = verified_manifest
        .manifest
        .artifacts
        .iter()
        .find(|artifact| {
            artifact.kind == request.artifact_kind && artifact.target == request.artifact_target
        })
        .cloned()
        .ok_or_else(|| ReleaseError::ArtifactUnavailable {
            kind: request.artifact_kind,
            target: request.artifact_target.clone(),
        })?;

    write_private_file(&staging.path().join(TRUST_POLICY_FILE_NAME), &policy)?;
    write_private_file(
        &staging.path().join(TRUST_SIGNATURE_FILE_NAME),
        &trust_signature,
    )?;
    write_private_file(&staging.path().join(RELEASE_MANIFEST_FILE_NAME), &manifest)?;
    write_private_file(
        &staging.path().join(RELEASE_SIGNATURE_FILE_NAME),
        &release_signature,
    )?;

    let artifact_directory = staging.path().join(ARTIFACT_DIRECTORY_NAME);
    sirinvpn_platform::files::create_private_directory(&artifact_directory)?;
    let artifact_path = artifact_directory.join(&artifact.file_name);
    fetch_exact_file(
        client,
        source_file_url(&source, &artifact.file_name)?,
        &artifact.file_name,
        artifact.size_bytes,
        &artifact_path,
    )
    .await?;

    let verified = verify_release_artifact_with_trust_policy(
        &manifest,
        &release_signature,
        &trust,
        &artifact_directory,
        request.artifact_kind,
        &request.artifact_target,
    )?;
    sync_directory(&artifact_directory)?;
    sync_directory(staging.path())?;
    commit_staging(staging, &destination)?;

    Ok(FetchedRelease {
        release_version: verified.manifest.release_version,
        release_sequence: verified.manifest.release_sequence,
        channel: verified.manifest.channel,
        security_update: verified.manifest.security_update,
        trust_policy_sequence: trust.policy.sequence,
        root_key_id_sha256: trust.root_key_id_sha256,
        release_key_id_sha256: verified.key_id_sha256,
        artifact: verified.artifact,
        artifact_directory: destination.join(ARTIFACT_DIRECTORY_NAME),
        bundle_directory: destination,
    })
}

pub fn validate_source_url(value: &str) -> Result<Url, FetchError> {
    if value.is_empty() || value.len() > MAX_SOURCE_URL_BYTES {
        return Err(FetchError::InvalidSourceUrl);
    }
    let source = Url::parse(value).map_err(|_| FetchError::InvalidSourceUrl)?;
    if source.scheme() != "https" {
        return Err(FetchError::SourceMustUseHttps);
    }
    if source.host_str().is_none() || source.cannot_be_a_base() {
        return Err(FetchError::InvalidSourceUrl);
    }
    if !source.username().is_empty()
        || source.password().is_some()
        || source.query().is_some()
        || source.fragment().is_some()
    {
        return Err(FetchError::SourceContainsPrivateData);
    }
    if !source.path().ends_with('/') {
        return Err(FetchError::SourceIsNotDirectory);
    }
    Ok(source)
}

fn validate_artifact_target(value: &str) -> Result<(), FetchError> {
    if value.is_empty() || value.len() > MAX_ARTIFACT_TARGET_BYTES {
        return Err(FetchError::InvalidArtifactTarget);
    }
    Ok(())
}

fn validate_destination(destination: &Path) -> Result<PathBuf, FetchError> {
    if !destination.is_absolute() {
        return Err(FetchError::InvalidDestination);
    }
    let file_name = destination
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or(FetchError::InvalidDestination)?;
    let parent = destination.parent().ok_or(FetchError::InvalidDestination)?;
    let canonical_parent = fs::canonicalize(parent).map_err(|_| FetchError::InvalidDestination)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| FetchError::InvalidDestination)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(FetchError::InvalidDestination);
    }
    let canonical_destination = canonical_parent.join(file_name);
    #[cfg(not(windows))]
    if canonical_destination != destination {
        return Err(FetchError::InvalidDestination);
    }
    #[cfg(windows)]
    validate_windows_destination(destination, &canonical_destination)?;
    match fs::symlink_metadata(destination) {
        Ok(_) => Err(FetchError::DestinationExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(canonical_destination),
        Err(error) => Err(FetchError::Io(error)),
    }
}

fn source_file_url(source: &Url, file_name: &str) -> Result<Url, FetchError> {
    source
        .join(file_name)
        .map_err(|_| FetchError::InvalidSourceUrl)
}

async fn fetch_bounded(
    client: &Client,
    url: Url,
    resource: &str,
    maximum_bytes: u64,
) -> Result<Vec<u8>, FetchError> {
    let mut response = request(client, url, resource).await?;
    if response
        .content_length()
        .is_some_and(|length| length > maximum_bytes)
    {
        return Err(FetchError::ResponseTooLarge {
            resource: resource.to_owned(),
            maximum_bytes,
        });
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|source| FetchError::Request {
            resource: resource.to_owned(),
            source,
        })?
    {
        if (bytes.len() as u64)
            .checked_add(chunk.len() as u64)
            .is_none_or(|length| length > maximum_bytes)
        {
            return Err(FetchError::ResponseTooLarge {
                resource: resource.to_owned(),
                maximum_bytes,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn fetch_exact_file(
    client: &Client,
    url: Url,
    resource: &str,
    expected_bytes: u64,
    path: &Path,
) -> Result<(), FetchError> {
    let mut response = request(client, url, resource).await?;
    if response
        .content_length()
        .is_some_and(|length| length != expected_bytes)
    {
        return Err(FetchError::ResponseSizeMismatch {
            resource: resource.to_owned(),
        });
    }
    let mut file = sirinvpn_platform::files::create_private_file(path)?;
    let mut received = 0_u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|source| FetchError::Request {
            resource: resource.to_owned(),
            source,
        })?
    {
        received = received.checked_add(chunk.len() as u64).ok_or_else(|| {
            FetchError::ResponseSizeMismatch {
                resource: resource.to_owned(),
            }
        })?;
        if received > expected_bytes {
            return Err(FetchError::ResponseSizeMismatch {
                resource: resource.to_owned(),
            });
        }
        file.write_all(&chunk)?;
    }
    if received != expected_bytes {
        return Err(FetchError::ResponseSizeMismatch {
            resource: resource.to_owned(),
        });
    }
    file.sync_all()?;
    Ok(())
}

async fn request(
    client: &Client,
    url: Url,
    resource: &str,
) -> Result<reqwest::Response, FetchError> {
    let response = client
        .get(url)
        .header(ACCEPT, "application/octet-stream")
        .header(ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|source| FetchError::Request {
            resource: resource.to_owned(),
            source,
        })?;
    if response.status() != StatusCode::OK {
        return Err(FetchError::HttpStatus {
            resource: resource.to_owned(),
            status: response.status().as_u16(),
        });
    }
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .is_some_and(|value| value.as_bytes() != b"identity")
    {
        return Err(FetchError::EncodedResponse(resource.to_owned()));
    }
    Ok(response)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), FetchError> {
    let mut file = sirinvpn_platform::files::create_private_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), FetchError> {
    sirinvpn_platform::files::sync_directory(path)?;
    Ok(())
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn commit_staging(staging: TempDir, destination: &Path) -> Result<(), FetchError> {
    use nix::{
        errno::Errno,
        fcntl::{AT_FDCWD, RenameFlags, renameat2},
    };

    match renameat2(
        AT_FDCWD,
        staging.path(),
        AT_FDCWD,
        destination,
        RenameFlags::RENAME_NOREPLACE,
    ) {
        Ok(()) => {}
        Err(Errno::EEXIST) => return Err(FetchError::DestinationExists),
        Err(Errno::ENOSYS | Errno::EINVAL | Errno::EOPNOTSUPP) => {
            return Err(FetchError::AtomicCommitUnsupported);
        }
        Err(error) => {
            return Err(FetchError::Io(io::Error::from_raw_os_error(error as i32)));
        }
    }
    let _ = staging.keep();
    let parent = destination.parent().ok_or(FetchError::InvalidDestination)?;
    sirinvpn_platform::files::sync_directory(parent).map_err(|source| {
        FetchError::CommitDurability {
            path: destination.to_path_buf(),
            source,
        }
    })?;
    Ok(())
}

#[cfg(windows)]
fn commit_staging(staging: TempDir, destination: &Path) -> Result<(), FetchError> {
    sirinvpn_platform::files::rename_directory_noreplace(staging.path(), destination).map_err(
        |error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                FetchError::DestinationExists
            } else {
                FetchError::Io(error)
            }
        },
    )?;
    let _ = staging.keep();
    Ok(())
}

#[cfg(windows)]
fn validate_windows_destination(destination: &Path, canonical: &Path) -> Result<(), FetchError> {
    use std::{
        os::windows::fs::MetadataExt,
        path::{Component, Prefix},
    };
    fn comparable(path: &Path) -> Result<PathBuf, FetchError> {
        let mut components = path.components();
        let disk = match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(disk) | Prefix::VerbatimDisk(disk) => disk,
                _ => return Err(FetchError::InvalidDestination),
            },
            _ => return Err(FetchError::InvalidDestination),
        };
        if components.next() != Some(Component::RootDir) {
            return Err(FetchError::InvalidDestination);
        }
        let mut normalized = PathBuf::from(format!("{}:\\", char::from(disk.to_ascii_uppercase())));
        for component in components {
            let Component::Normal(name) = component else {
                return Err(FetchError::InvalidDestination);
            };
            normalized.push(name);
        }
        Ok(normalized)
    }
    if !comparable(destination)?
        .to_string_lossy()
        .eq_ignore_ascii_case(&comparable(canonical)?.to_string_lossy())
    {
        return Err(FetchError::InvalidDestination);
    }
    for parent in destination.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent)?;
        // Reject junctions and every other reparse-point kind, including ancestors.
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err(FetchError::InvalidDestination);
        }
    }
    Ok(())
}

#[cfg(not(any(windows, all(target_os = "linux", target_env = "gnu"))))]
fn commit_staging(_staging: TempDir, _destination: &Path) -> Result<(), FetchError> {
    Err(FetchError::AtomicCommitUnsupported)
}

#[cfg(test)]
mod tests;
