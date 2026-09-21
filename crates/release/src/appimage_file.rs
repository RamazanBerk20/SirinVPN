//! Replace one user-owned type-2 AppImage without elevation or executing a download.
use crate::{ReleaseArtifact, ReleaseError, digest_artifact};
use std::{
    fs::{self, File, Metadata},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub struct AppImageFile {
    path: PathBuf,
    original: Metadata,
    sha256: String,
    machine: u16,
}

impl AppImageFile {
    pub fn inspect(path: &Path, target: &str) -> Result<Self, ReleaseError> {
        let machine = match target {
            "x86_64-unknown-linux-gnu" => 62,
            "aarch64-unknown-linux-gnu" => 183,
            _ => return Err(ReleaseError::ClientUpdateUnsupported),
        };
        validate_parent(path)?;
        let file = sirinvpn_platform::files::open_no_follow(path)?;
        let original = file.metadata()?;
        validate_owner(&original)?;
        validate_header(file, machine)?;
        let (_, sha256) = digest_artifact(path)?;
        Ok(Self {
            path: path.to_owned(),
            original,
            sha256,
            machine,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// One local release record per portable installation path. No network or
    /// release-check history is retained. The directory belongs to the caller.
    pub fn state_key(&self) -> String {
        use sha2::{Digest, Sha256};
        use std::os::unix::ffi::OsStrExt;
        hex::encode(Sha256::digest(self.path.as_os_str().as_bytes()))
    }

    pub fn replace(
        &self,
        candidate: &Path,
        artifact: &ReleaseArtifact,
    ) -> Result<(), ReleaseError> {
        validate_parent(&self.path)?;
        let current = sirinvpn_platform::files::open_no_follow(&self.path)?;
        validate_owner(&current.metadata()?)?;
        if !same_inode(&self.original, &current.metadata()?)
            || digest_artifact(&self.path)?.1 != self.sha256
        {
            return Err(ReleaseError::ClientInstalledMismatch);
        }
        let source = sirinvpn_platform::files::open_no_follow(candidate)?;
        validate_header(
            sirinvpn_platform::files::open_no_follow(candidate)?,
            self.machine,
        )?;
        if digest_artifact(candidate)? != (artifact.size_bytes, artifact.sha256.clone()) {
            return Err(ReleaseError::InvalidInstalledPackageCache);
        }
        let parent = self
            .path
            .parent()
            .ok_or(ReleaseError::UnsafeInstalledState)?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".sirinvpn-appimage-")
            .tempfile_in(parent)?;
        // The initial mode is 0600. Grant execute permission only to complete,
        // independently rehashed bytes immediately before the atomic rename.
        let copied = std::io::copy(&mut source.take(artifact.size_bytes + 1), &mut temporary)?;
        temporary.flush()?;
        if copied != artifact.size_bytes
            || digest_artifact(temporary.path())? != (artifact.size_bytes, artifact.sha256.clone())
        {
            return Err(ReleaseError::InvalidInstalledPackageCache);
        }
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(self.original.mode() & 0o777))?;
        temporary.as_file().sync_all()?;
        let latest = fs::symlink_metadata(&self.path)?;
        if !same_inode(&self.original, &latest) || digest_artifact(&self.path)?.1 != self.sha256 {
            return Err(ReleaseError::ClientInstalledMismatch);
        }
        // Both paths share a directory/filesystem; rename exposes either the
        // complete old file or complete new file. The old bytes remain cached.
        temporary.persist(&self.path).map_err(|error| error.error)?;
        sirinvpn_platform::files::sync_directory(parent)?;
        Ok(())
    }
}

fn same_inode(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && right.file_type().is_file()
        && right.nlink() == 1
}

fn validate_parent(path: &Path) -> Result<(), ReleaseError> {
    if !path.is_absolute() || fs::canonicalize(path)? != path {
        return Err(ReleaseError::UnsafeInstalledState);
    }
    let parent = path.parent().ok_or(ReleaseError::UnsafeInstalledState)?;
    let uid = nix::unistd::Uid::effective().as_raw();
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        let sticky_root =
            ancestor != parent && metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.file_type().is_dir()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || metadata.mode() & 0o022 != 0 && !sticky_root
        {
            return Err(ReleaseError::UnsafeInstalledState);
        }
    }
    if fs::metadata(parent)?.uid() != uid {
        return Err(ReleaseError::UnsafeInstalledState);
    }
    Ok(())
}

fn validate_owner(metadata: &Metadata) -> Result<(), ReleaseError> {
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o7022 != 0
        || metadata.mode() & 0o100 == 0
    {
        return Err(ReleaseError::UnsafeInstalledState);
    }
    Ok(())
}

fn validate_header(mut file: File, machine: u16) -> Result<(), ReleaseError> {
    let mut bytes = [0; 20];
    file.read_exact(&mut bytes)?;
    if &bytes[..7] != b"\x7fELF\x02\x01\x01"
        || &bytes[8..11] != b"AI\x02"
        || u16::from_le_bytes([bytes[18], bytes[19]]) != machine
    {
        return Err(ReleaseError::ClientUpdateUnsupported);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn artifact(path: &Path, value: u8) -> ReleaseArtifact {
        let mut bytes = [value; 128];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[8..11].copy_from_slice(b"AI\x02");
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        let (size_bytes, sha256) = digest_artifact(path).unwrap();
        ReleaseArtifact {
            kind: crate::ArtifactKind::LinuxAppImage,
            target: "x86_64-unknown-linux-gnu".into(),
            file_name: "vpn.AppImage".into(),
            size_bytes,
            sha256,
        }
    }
    #[test]
    fn replaces_exact_owned_file_and_rejects_changed_target_or_candidate() {
        let root = tempfile::tempdir().unwrap();
        let current = root.path().join("VPN with spaces.AppImage");
        let candidate = root.path().join("candidate.AppImage");
        let old = artifact(&current, 1);
        let new = artifact(&candidate, 2);
        let original = AppImageFile::inspect(&current, &old.target).unwrap();
        original.replace(&candidate, &new).unwrap();
        assert_eq!(digest_artifact(&current).unwrap().1, new.sha256);
        assert_eq!(fs::metadata(&current).unwrap().mode() & 0o777, 0o700);
        assert!(original.replace(&candidate, &new).is_err());
        let fresh = AppImageFile::inspect(&current, &old.target).unwrap();
        artifact(&candidate, 3);
        assert!(fresh.replace(&candidate, &new).is_err());
        assert_eq!(digest_artifact(&current).unwrap().1, new.sha256);
    }
    #[test]
    fn rejects_links_unsafe_modes_and_wrong_architecture() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("vpn.AppImage");
        let item = artifact(&path, 1);
        let alias = root.path().join("alias");
        symlink(&path, &alias).unwrap();
        assert!(AppImageFile::inspect(&alias, &item.target).is_err());
        fs::hard_link(&path, root.path().join("hard")).unwrap();
        assert!(AppImageFile::inspect(&path, &item.target).is_err());
        fs::remove_file(root.path().join("hard")).unwrap();
        assert!(AppImageFile::inspect(&path, "aarch64-unknown-linux-gnu").is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(AppImageFile::inspect(&path, &item.target).is_err());
    }
}
