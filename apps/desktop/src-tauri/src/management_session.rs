//! Platform identity boundary shared by member administration commands.
use sirinvpn_core::ManagementClient;
use sirinvpn_core::SecretStore;
use sirinvpn_protocol::ServerProfile;
use std::sync::{LazyLock, Mutex};
use tauri::Manager;

#[derive(Clone)]
struct CachedClient {
    profile: ServerProfile,
    connection: String,
    revision: u64,
    client: ManagementClient,
}
static CLIENT: Mutex<Option<CachedClient>> = Mutex::new(None);
static GENERATION: LazyLock<tokio::sync::watch::Sender<u64>> =
    LazyLock::new(|| tokio::sync::watch::channel(0).0);

pub(crate) fn invalidate() {
    *CLIENT.lock().unwrap_or_else(|error| error.into_inner()) = None;
    GENERATION.send_modify(|generation| *generation = generation.wrapping_add(1));
}

fn cached(server_id: &str, connection: &str, revision: u64) -> Option<CachedClient> {
    CLIENT
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .filter(|entry| {
            entry.profile.id.to_string() == server_id
                && entry.connection == connection
                && entry.revision == revision
        })
        .cloned()
}

fn retain(
    profile: ServerProfile,
    connection: String,
    revision: u64,
    client: ManagementClient,
) -> CachedClient {
    let entry = CachedClient {
        profile,
        connection,
        revision,
        client,
    };
    *CLIENT.lock().unwrap_or_else(|error| error.into_inner()) = Some(entry.clone());
    entry
}

pub(crate) struct ManagementSession {
    pub profile: ServerProfile,
    client: ManagementClient,
    generation: u64,
}

impl std::ops::Deref for ManagementSession {
    type Target = ManagementClient;
    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl ManagementSession {
    /// Read-only HTTP never owns the connection mutation gate. Disconnect
    /// drops the request immediately; an old response cannot update a new session.
    pub(crate) async fn read<T>(
        &self,
        operation: impl std::future::Future<Output = Result<T, sirinvpn_core::ManagementError>>,
    ) -> Result<T, String> {
        read_generation(self.generation, operation).await
    }
    pub(crate) async fn retain_access(
        &self,
        app: &tauri::AppHandle,
        role: sirinvpn_protocol::ServerRole,
        administrator: bool,
    ) -> Result<(), String> {
        if self.profile.role == role && self.profile.administrator == administrator {
            return Ok(());
        }
        let mut next = self.profile.clone();
        next.role = role;
        next.administrator = administrator;
        app.state::<crate::AppState>()
            .paths
            .profile_store()
            .upsert(next)
            .map_err(crate::safe_error)?;
        Ok(())
    }
}

pub(crate) async fn connected(
    app: &tauri::AppHandle,
    server_id: &str,
) -> Result<ManagementSession, String> {
    prepare(app, server_id, false).await
}

pub(crate) async fn connected_read(
    app: &tauri::AppHandle,
    server_id: &str,
) -> Result<ManagementSession, String> {
    prepare(app, server_id, true).await
}

async fn prepare(
    app: &tauri::AppHandle,
    server_id: &str,
    read_only: bool,
) -> Result<ManagementSession, String> {
    let generation = *GENERATION.borrow();
    {
        let state = app.state::<crate::AppState>();
        let paths = state.paths.clone();
        let server_id = server_id.to_owned();
        let entry = tauri::async_runtime::spawn_blocking(move || {
            let profile = crate::identity::find_profile(&paths, &server_id)?;
            let status = crate::helper::invoke_helper("status", None).map_err(crate::safe_error)?;
            if status.server_id != Some(profile.id)
                || status.state != crate::ConnectionState::Connected
            {
                return Err("Connect to this server before managing access.".to_owned());
            }
            let connection = status.counter_epoch.unwrap_or_default();
            if let Some(entry) =
                cached(&server_id, &connection, 0).filter(|entry| entry.profile == profile)
            {
                return Ok(entry);
            }
            let secret = paths
                .secret_store()
                .get(&profile.identity_reference)
                .map_err(crate::safe_error)?;
            let client = ManagementClient::new(&profile, &secret).map_err(crate::safe_error)?;
            Ok(retain(profile, connection, 0, client))
        })
        .await
        .map_err(|_| "The management worker was interrupted.".to_owned())??;
        let _ = read_only;
        Ok(ManagementSession {
            profile: entry.profile,
            client: entry.client,
            generation,
        })
    }
}

async fn read_generation<T>(
    generation: u64,
    operation: impl std::future::Future<Output = Result<T, sirinvpn_core::ManagementError>>,
) -> Result<T, String> {
    let mut changes = GENERATION.subscribe();
    let changed = || "The connection changed. Refresh this server's current data.".to_owned();
    if *changes.borrow() != generation {
        return Err(changed());
    }
    let result = tokio::select! {
        result = operation => result.map_err(crate::safe_error),
        _ = changes.changed() => Err(changed()),
    };
    if *changes.borrow() != generation {
        return Err(changed());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn disconnect_cancels_pending_reads_and_rejects_late_results() {
        let generation = *GENERATION.borrow();
        let (ready, started) = tokio::sync::oneshot::channel();
        let pending = tokio::spawn(async move {
            read_generation(generation, async {
                let _ = ready.send(());
                std::future::pending::<Result<(), sirinvpn_core::ManagementError>>().await
            })
            .await
        });
        started.await.unwrap();
        invalidate();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(250), pending)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(read_generation(generation, async { Ok(()) }).await.is_err());
        let current = *GENERATION.borrow();
        assert!(read_generation(current, async { Ok(()) }).await.is_ok());
    }
}
