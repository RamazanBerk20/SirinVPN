use super::*;
use fs2::FileExt;
use serde::de::DeserializeOwned;
use sirinvpn_release_fetch::{
    ARTIFACT_DIRECTORY_NAME, RELEASE_MANIFEST_FILE_NAME, RELEASE_NOTES_FILE_NAME,
    RELEASE_SIGNATURE_FILE_NAME, TRUST_POLICY_FILE_NAME, TRUST_SIGNATURE_FILE_NAME,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
    time::Duration,
};

pub fn operation_lock() -> anyhow::Result<File> {
    ensure_directory()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(RELEASE_DIRECTORY).join("operations.lock"))?;
    validate_private_file(&file)?;
    FileExt::try_lock_exclusive(&file)
        .map_err(|_| anyhow::anyhow!("another VPS release operation is running"))?;
    Ok(file)
}

pub fn ensure_directory() -> anyhow::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(RELEASE_DIRECTORY) {
        Ok(()) => {
            File::open("/var/lib")?.sync_all()?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(RELEASE_DIRECTORY)?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && metadata.uid() == 0 && metadata.mode() & 0o777 == 0o700,
        "the VPS release directory has unsafe permissions"
    );
    Ok(())
}

pub fn read_record<T: DeserializeOwned>(name: &str) -> anyhow::Result<Option<T>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(RELEASE_DIRECTORY).join(name))
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    validate_private_file(&file)?;
    anyhow::ensure!(
        file.metadata()?.len() <= 8192,
        "VPS release settings are oversized"
    );
    let mut bytes = Vec::new();
    file.take(8193).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 8192, "VPS release settings are oversized");
    Ok(Some(serde_json::from_slice(&bytes)?))
}

pub fn write_record<T: Serialize>(name: &str, record: &T) -> anyhow::Result<()> {
    ensure_directory()?;
    let bytes = serde_json::to_vec(record)?;
    anyhow::ensure!(bytes.len() <= 8192, "VPS release settings are oversized");
    let mut temporary = tempfile::Builder::new()
        .prefix(".settings-")
        .tempfile_in(RELEASE_DIRECTORY)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(Path::new(RELEASE_DIRECTORY).join(name))
        .map_err(|error| error.error)?;
    File::open(RELEASE_DIRECTORY)?.sync_all()?;
    Ok(())
}

fn validate_private_file(file: &File) -> anyhow::Result<()> {
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o777 == 0o600,
        "VPS release state has unsafe ownership or permissions"
    );
    Ok(())
}

pub fn fetch_unprivileged(
    source: &str,
    channel: ReleaseChannel,
) -> anyhow::Result<tempfile::TempDir> {
    sirinvpn_release_fetch::validate_source_url(source)?;
    let user = nix::unistd::User::from_name("sirinvpn-update-fetch")?.ok_or_else(|| {
        anyhow::anyhow!("the release download account is unavailable; repair the server components")
    })?;
    anyhow::ensure!(
        !user.uid.is_root(),
        "the release fetch account must be unprivileged"
    );
    let staging = tempfile::Builder::new()
        .prefix("sirinvpn-release-fetch-")
        .tempdir_in("/var/tmp")?;
    nix::unistd::chown(staging.path(), Some(user.uid), Some(user.gid))?;
    let destination = staging.path().join("bundle");
    host::run_command(
        Command::new("/usr/bin/timeout")
            .args([
                "--signal=TERM",
                "--kill-after=5s",
                "16m",
                "/usr/sbin/runuser",
                "-u",
                "sirinvpn-update-fetch",
                "--",
                host::UPDATER_BINARY,
                "release",
                "fetch",
                "--source",
            ])
            .arg(source)
            .arg("--channel")
            .arg(channel.to_string())
            .arg("--destination")
            .arg(&destination),
        Duration::from_secs(17 * 60),
        "bounded unprivileged release download",
    )?;
    let verified = VerifiedReleaseBundle::open(&destination, ArtifactKind::ServerElf, target()?)?;
    let owned = import_bundle(&verified)?;
    Ok(owned)
}

pub fn import_bundle(verified: &VerifiedReleaseBundle) -> anyhow::Result<tempfile::TempDir> {
    ensure_directory()?;
    let owned = tempfile::Builder::new()
        .prefix(".verified-")
        .tempdir_in(RELEASE_DIRECTORY)?;
    copy_bundle(verified, owned.path())?;
    File::open(owned.path())?.sync_all()?;
    // The downloader's UID can write its staging area. Reverify the root-owned
    // copy before any command can execute it or preserve it for installation.
    VerifiedReleaseBundle::open(owned.path(), ArtifactKind::ServerElf, target()?)?;
    Ok(owned)
}

/// Writes the verified metadata, the verified notes when present, and the artifact into `into`.
fn copy_bundle(verified: &VerifiedReleaseBundle, into: &Path) -> anyhow::Result<()> {
    for (name, bytes) in [
        (RELEASE_MANIFEST_FILE_NAME, &verified.manifest_bytes),
        (RELEASE_SIGNATURE_FILE_NAME, &verified.signature_bytes),
        (TRUST_POLICY_FILE_NAME, &verified.trust_policy_bytes),
        (TRUST_SIGNATURE_FILE_NAME, &verified.trust_signature_bytes),
    ]
    .into_iter()
    .chain(
        verified
            .release_notes
            .as_ref()
            .map(|(notes, _)| (RELEASE_NOTES_FILE_NAME, notes)),
    ) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(into.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    let artifacts = into.join(ARTIFACT_DIRECTORY_NAME);
    fs::DirBuilder::new().mode(0o700).create(&artifacts)?;
    let artifact = &verified.verified.artifact;
    let source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(verified.artifact_directory.join(&artifact.file_name))?;
    anyhow::ensure!(
        source.metadata()?.file_type().is_file(),
        "release artifact is not a regular file"
    );
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(artifacts.join(&artifact.file_name))?;
    let copied = std::io::copy(&mut source.take(artifact.size_bytes + 1), &mut destination)?;
    anyhow::ensure!(
        copied == artifact.size_bytes,
        "release artifact size changed during import"
    );
    destination.sync_all()?;
    File::open(&artifacts)?.sync_all()?;
    Ok(())
}

pub fn publish_pending(bundle: tempfile::TempDir) -> anyhow::Result<()> {
    let path = Path::new(RELEASE_DIRECTORY).join("pending");
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.file_type().is_dir() && metadata.uid() == 0,
                "pending release state is unsafe"
            );
            fs::remove_dir_all(&path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::rename(bundle.path(), &path)?;
    File::open(RELEASE_DIRECTORY)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sirinvpn_release::{
        ArtifactKind, ReleaseArtifact, ReleaseChannel, ReleaseManifest, VerifiedArtifactRelease,
    };

    #[test]
    fn the_root_owned_copy_keeps_verified_notes() {
        let staging = tempfile::tempdir().unwrap();
        let artifacts = staging.path().join(ARTIFACT_DIRECTORY_NAME);
        fs::create_dir(&artifacts).unwrap();
        fs::write(artifacts.join("sirinvpn-server"), b"binary").unwrap();
        let artifact = ReleaseArtifact {
            kind: ArtifactKind::ServerElf,
            target: "x86_64-unknown-linux-gnu".into(),
            file_name: "sirinvpn-server".into(),
            size_bytes: 6,
            sha256: "0".repeat(64),
        };
        let mut verified = VerifiedReleaseBundle {
            manifest_bytes: b"manifest".to_vec(),
            signature_bytes: b"signature".to_vec(),
            trust_policy_bytes: b"policy".to_vec(),
            trust_signature_bytes: b"policy signature".to_vec(),
            release_notes: Some((b"notes".to_vec(), "Reconnects faster.".into())),
            verified: VerifiedArtifactRelease {
                manifest: ReleaseManifest {
                    schema_version: 1,
                    product: "sirinvpn".into(),
                    release_version: "1.0.2".into(),
                    release_sequence: 2,
                    channel: ReleaseChannel::Stable,
                    security_update: false,
                    artifacts: vec![artifact.clone()],
                    state_compatibility: Vec::new(),
                },
                manifest_sha256: "1".repeat(64),
                key_id_sha256: "2".repeat(64),
                artifact,
            },
            artifact_directory: artifacts,
        };
        let owned = tempfile::tempdir().unwrap();
        copy_bundle(&verified, owned.path()).unwrap();
        assert_eq!(
            fs::read(owned.path().join(RELEASE_NOTES_FILE_NAME)).unwrap(),
            b"notes"
        );
        assert_eq!(
            fs::read(
                owned
                    .path()
                    .join(ARTIFACT_DIRECTORY_NAME)
                    .join("sirinvpn-server")
            )
            .unwrap(),
            b"binary"
        );

        // A bundle without notes gets no notes file.
        verified.release_notes = None;
        let bare = tempfile::tempdir().unwrap();
        copy_bundle(&verified, bare.path()).unwrap();
        assert!(!bare.path().join(RELEASE_NOTES_FILE_NAME).exists());
    }
}
