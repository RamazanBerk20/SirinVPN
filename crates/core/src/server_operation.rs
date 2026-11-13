//! One identity or endpoint operation per server at a time, across the CLI, desktop and
//! Android processes. Key rotation and endpoint transitions both rewrite how this
//! device reaches its VPS; a second runner fails fast instead of racing the first.
use crate::ClientPaths;
use fs2::FileExt;
use sirinvpn_protocol::ServerId;
use std::{fs, io};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerOperationError {
    #[error(
        "a key rotation or endpoint update for this server is already in progress; wait for it to finish, then retry"
    )]
    AlreadyInProgress,
    #[error("the server operation lock is unavailable: {0}")]
    Io(#[from] io::Error),
}

/// Held for the whole operation; dropping it releases the server.
#[derive(Debug)]
pub struct ServerOperationLock {
    _lock: fs::File,
}

impl ServerOperationLock {
    pub fn acquire(paths: &ClientPaths, server_id: ServerId) -> Result<Self, ServerOperationError> {
        let directory = paths.configuration_directory.join("server-operations");
        sirinvpn_platform::files::create_private_directory(&directory)?;
        let path = directory.join(format!("{server_id}.lock"));
        if fs::symlink_metadata(&path)
            .is_ok_and(|metadata| !metadata.is_file() || metadata.file_type().is_symlink())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "server operation lock is not a regular file",
            )
            .into());
        }
        let lock = sirinvpn_platform::files::open_private_lock(&path)?;
        match lock.try_lock_exclusive() {
            Ok(()) => Ok(Self { _lock: lock }),
            Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
                Err(ServerOperationError::AlreadyInProgress)
            }
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_runner_sees_already_in_progress_until_the_first_finishes() {
        let directory = tempfile::tempdir().unwrap();
        let paths = ClientPaths::under(directory.path().into());
        let server = ServerId::new();
        let first = ServerOperationLock::acquire(&paths, server).unwrap();
        // Each acquire opens its own file description, as another process would.
        assert!(matches!(
            ServerOperationLock::acquire(&paths, server),
            Err(ServerOperationError::AlreadyInProgress)
        ));
        // Other servers are independent.
        drop(ServerOperationLock::acquire(&paths, ServerId::new()).unwrap());
        drop(first);
        ServerOperationLock::acquire(&paths, server).unwrap();
    }
}
