use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sirinvpn_protocol::{ServerId, ServerProfile};
use std::{
    fs, io,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProfileStoreError {
    #[error("profile store operation failed: {0}")]
    Io(#[from] io::Error),
    #[error("profile store contains invalid data")]
    InvalidData,
    #[error("server profile was not found")]
    NotFound,
    #[error("server profile already exists")]
    AlreadyExists,
}

#[derive(Default, Serialize, Deserialize)]
struct ProfileDocument {
    schema_version: u16,
    servers: Vec<ServerProfile>,
}

pub struct ProfileStore {
    path: PathBuf,
}

impl ProfileStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn load(&self) -> Result<Vec<ServerProfile>, ProfileStoreError> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let document: ProfileDocument =
                    serde_json::from_slice(&bytes).map_err(|_| ProfileStoreError::InvalidData)?;
                if document.schema_version != 1 {
                    return Err(ProfileStoreError::InvalidData);
                }
                Ok(document.servers)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn upsert(&self, profile: ServerProfile) -> Result<(), ProfileStoreError> {
        self.mutate(move |profiles| {
            if let Some(existing) = profiles.iter_mut().find(|item| item.id == profile.id) {
                *existing = profile;
            } else {
                profiles.push(profile);
            }
            Ok(())
        })
    }

    pub fn insert(&self, profile: ServerProfile) -> Result<(), ProfileStoreError> {
        self.mutate(move |profiles| {
            if profiles.iter().any(|item| item.id == profile.id) {
                return Err(ProfileStoreError::AlreadyExists);
            }
            profiles.push(profile);
            Ok(())
        })
    }

    /// Commit a signed checkpoint under the profile lock, preserving concurrent
    /// presentation changes and refusing a stale generation or changed identity.
    pub fn apply_endpoint_checkpoint(
        &self,
        response: sirinvpn_protocol::EndpointTransitionResponse,
    ) -> Result<ServerProfile, ProfileStoreError> {
        let decoded = crate::DecodedEndpointTransition::from_response(response)
            .map_err(|_| ProfileStoreError::InvalidData)?;
        self.mutate(move |profiles| {
            let current = profiles
                .iter_mut()
                .find(|profile| profile.id == decoded.response().claims.server_id)
                .ok_or(ProfileStoreError::NotFound)?;
            let candidate = decoded
                .candidate_profile(current)
                .map_err(|_| ProfileStoreError::InvalidData)?;
            *current = candidate.clone();
            Ok(candidate)
        })
    }

    /// Change collection metadata under the store lock; never replace key or endpoint fields.
    pub fn update_presentation(
        &self,
        id: ServerId,
        name: Option<String>,
        favorite: Option<bool>,
    ) -> Result<(), ProfileStoreError> {
        if name
            .as_ref()
            .is_some_and(|value| sirinvpn_protocol::validate_server_name(value.trim()).is_err())
        {
            return Err(ProfileStoreError::InvalidData);
        }
        self.mutate(move |profiles| {
            let profile = profiles
                .iter_mut()
                .find(|profile| profile.id == id)
                .ok_or(ProfileStoreError::NotFound)?;
            if let Some(name) = name {
                profile.name = name.trim().to_owned();
            }
            if let Some(favorite) = favorite {
                profile.favorite = favorite;
            }
            Ok(())
        })
    }

    pub fn remove(&self, id: ServerId) -> Result<(), ProfileStoreError> {
        self.mutate(move |profiles| {
            let previous_length = profiles.len();
            profiles.retain(|profile| profile.id != id);
            if profiles.len() == previous_length {
                return Err(ProfileStoreError::NotFound);
            }
            Ok(())
        })
    }

    fn mutate<T>(
        &self,
        operation: impl FnOnce(&mut Vec<ServerProfile>) -> Result<T, ProfileStoreError>,
    ) -> Result<T, ProfileStoreError> {
        let parent = self.path.parent().ok_or_else(|| {
            ProfileStoreError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing parent",
            ))
        })?;
        sirinvpn_platform::files::create_private_directory(parent)?;

        let lock_path = self.path.with_extension("lock");
        let lock = sirinvpn_platform::files::open_private_lock(&lock_path)?;
        lock.lock_exclusive()?;

        let mut servers = self.load()?;
        let result = operation(&mut servers)?;
        self.write_locked(parent, servers)?;
        FileExt::unlock(&lock)?;
        Ok(result)
    }

    fn write_locked(
        &self,
        _parent: &Path,
        servers: Vec<ServerProfile>,
    ) -> Result<(), ProfileStoreError> {
        let document = ProfileDocument {
            schema_version: 1,
            servers,
        };
        let bytes =
            serde_json::to_vec_pretty(&document).map_err(|_| ProfileStoreError::InvalidData)?;
        sirinvpn_platform::files::atomic_write(&self.path, &bytes, true)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sirinvpn_protocol::{ServerEndpoint, ServerRole};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn presentation_changes_preserve_identity_and_survive_reload() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profiles.json");
        let store = ProfileStore::new(path.clone());
        let original = profile("Original");
        store.insert(original.clone()).unwrap();
        store
            .update_presentation(original.id, Some("My VPS".into()), Some(true))
            .unwrap();
        let mut expected = original.clone();
        expected.name = "My VPS".into();
        expected.favorite = true;
        assert_eq!(
            ProfileStore::new(path).load().unwrap(),
            vec![expected.clone()]
        );
        for invalid in ["", "   ", "bad\nname"] {
            assert!(
                store
                    .update_presentation(original.id, Some(invalid.into()), None)
                    .is_err()
            );
            assert_eq!(store.load().unwrap(), vec![expected.clone()]);
        }
        assert!(
            store
                .update_presentation(ServerId::new(), None, Some(true))
                .is_err()
        );
    }

    fn profile(name: &str) -> ServerProfile {
        ServerProfile {
            favorite: false,
            schema_version: 1,
            id: ServerId::new(),
            name: name.into(),
            endpoint: ServerEndpoint {
                host: "203.0.113.4".into(),
                wireguard_port: 51_820,
            },
            endpoint_generation: 0,
            pending_previous_endpoint: None,
            pending_previous_transports: None,
            endpoint_discovery_port: None,
            alternate_endpoint_hosts: Vec::new(),
            client_tunnel_address: IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2)),
            server_tunnel_address: IpAddr::V4(Ipv4Addr::new(10, 77, 0, 1)),
            ipv6_tunnel_enabled: false,
            server_wireguard_public_key: "public".into(),
            pinned_server_certificate_pem: "certificate".into(),
            client_management_certificate_pem: "client-certificate".into(),
            identity_reference: "identity".into(),
            role: ServerRole::Owner,
            administrator: false,
            member_id: None,
            device_id: None,
            obfuscated_udp: None,
            tcp_fallback: None,
            tls_like: None,
        }
    }

    #[test]
    fn upsert_is_atomic_and_replaces_by_id() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(directory.path().join("profiles.json"));
        let mut item = profile("First");
        let id = item.id;
        store.upsert(item.clone()).unwrap();
        item.name = "Renamed".into();
        store.upsert(item).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, id);
        assert_eq!(loaded[0].name, "Renamed");
    }

    #[test]
    fn insert_rejects_an_existing_server_without_replacing_it() {
        let directory = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(directory.path().join("profiles.json"));
        let original = profile("Original");
        let mut conflicting = original.clone();
        conflicting.name = "Conflicting".into();
        store.insert(original.clone()).unwrap();
        assert!(matches!(
            store.insert(conflicting),
            Err(ProfileStoreError::AlreadyExists)
        ));
        assert_eq!(store.load().unwrap(), vec![original]);
    }

    #[test]
    fn legacy_profiles_expand_with_safe_endpoint_defaults() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profiles.json");
        let original = profile("Legacy");
        let mut encoded = serde_json::to_value(&original).unwrap();
        let object = encoded.as_object_mut().unwrap();
        object.remove("endpoint_generation");
        object.remove("pending_previous_endpoint");
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "servers": [encoded],
            }))
            .unwrap(),
        )
        .unwrap();

        let loaded = ProfileStore::new(path).load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].endpoint_generation, 0);
        assert_eq!(loaded[0].pending_previous_endpoint, None);
    }
}
