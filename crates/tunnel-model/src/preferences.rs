//! One current configuration per locally retained server. No traffic or connection history.
use crate::{ConnectionPolicy, TunnelRoutingMode, TunnelRoutingPolicy};
use serde::{Deserialize, Serialize};
use sirinvpn_protocol::{NetworkProfile, ServerId, TransportPreference};
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Mutex,
};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionPreferences {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub android_applications: Option<sirinvpn_protocol::AndroidApplicationRouting>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_mtu: Option<u16>,
    pub transport: TransportPreference,
    pub network_profile: NetworkProfile,
    pub policy: ConnectionPolicy,
    pub routing: TunnelRoutingPolicy,
}

impl ConnectionPreferences {
    pub fn validated(mut self) -> Result<Self, String> {
        self.android_applications = self
            .android_applications
            .map(|value| value.validated())
            .transpose()
            .map_err(str::to_owned)?
            .filter(|value| value.mode != sirinvpn_protocol::AndroidApplicationMode::All);
        if let Some(value) = self.manual_mtu {
            sirinvpn_protocol::MtuPolicy::Manual { value }
                .validate(false)
                .map_err(str::to_owned)?;
        }
        self.routing = match self.routing.mode {
            TunnelRoutingMode::SelectedApplications => {
                if !self.routing.included_routes.is_empty() {
                    return Err("Application routing must not include a CIDR list.".into());
                }
                TunnelRoutingPolicy::selected_applications(self.routing.allow_lan)
            }
            TunnelRoutingMode::FullTunnel => {
                if !self.routing.included_routes.is_empty() {
                    return Err("Full tunnel must not include a selected-route list.".into());
                }
                TunnelRoutingPolicy::full_tunnel(self.routing.allow_lan)
            }
            TunnelRoutingMode::SelectedRoutes => TunnelRoutingPolicy::selected_routes(
                self.routing.included_routes,
                self.routing.allow_lan,
            )?,
        };
        Ok(self)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u16,
    preferences: ConnectionPreferences,
}

pub struct ConnectionPreferenceStore {
    directory: PathBuf,
    operation: Mutex<()>,
}

impl ConnectionPreferenceStore {
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            operation: Mutex::new(()),
        }
    }
    fn path(&self, id: ServerId) -> PathBuf {
        self.directory.join(format!("{id}.json"))
    }
    pub fn get(&self, id: ServerId) -> Result<ConnectionPreferences, String> {
        let _guard = self
            .operation
            .lock()
            .map_err(|_| "Connection preferences are unavailable.")?;
        read(&self.path(id)).map_err(|_| {
            "Saved connection preferences could not be read. The existing file was preserved."
                .into()
        })
    }
    pub fn set(
        &self,
        id: ServerId,
        preferences: ConnectionPreferences,
    ) -> Result<ConnectionPreferences, String> {
        let preferences = preferences.validated()?;
        let _guard = self
            .operation
            .lock()
            .map_err(|_| "Connection preferences are unavailable.")?;
        let path = self.path(id);
        read(&path).map_err(
            |_| "Existing connection preferences could not be read and were not overwritten.",
        )?;
        let write = || -> io::Result<()> {
            sirinvpn_platform::files::create_private_directory(&self.directory)?;
            let bytes = serde_json::to_vec_pretty(&Document {
                schema_version: if preferences.android_applications.is_some() {
                    5
                } else if preferences.routing.mode == TunnelRoutingMode::SelectedApplications {
                    4
                } else if preferences.manual_mtu.is_some() {
                    3
                } else {
                    2
                },
                preferences: preferences.clone(),
            })?;
            sirinvpn_platform::files::atomic_write(&path, &bytes, true)
        };
        write().map_err(
            |_| "Connection preferences could not be saved. Previous settings remain stored.",
        )?;
        Ok(preferences)
    }
    pub fn forget(&self, id: ServerId) -> Result<(), String> {
        let _guard = self
            .operation
            .lock()
            .map_err(|_| "Connection preferences are unavailable.")?;
        match fs::remove_file(self.path(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err("Connection preferences could not be removed.".into()),
        }
    }
}

fn read(path: &Path) -> io::Result<ConnectionPreferences> {
    let file = match sirinvpn_platform::files::open_no_follow(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(ConnectionPreferences::default());
        }
        Err(e) => return Err(e),
    };
    let mut bytes = Vec::new();
    file.take(16385).read_to_end(&mut bytes)?;
    if bytes.len() > 16384 {
        return Err(io::Error::other("preferences too large"));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        == Some(1)
    {
        let old: LegacyDocument = serde_json::from_value(value)?;
        if old.preferences.routing.mode == TunnelRoutingMode::SelectedApplications {
            return Err(io::Error::other("unsupported legacy routing mode"));
        }
        return ConnectionPreferences {
            android_applications: None,
            manual_mtu: None,
            transport: old.preferences.transport,
            network_profile: old.preferences.network_profile,
            policy: ConnectionPolicy::legacy(old.preferences.persistent_protection),
            routing: old.preferences.routing,
        }
        .validated()
        .map_err(io::Error::other);
    }
    let document: Document = serde_json::from_value(value)?;
    if !matches!(document.schema_version, 2..=5)
        || (document.schema_version < 5 && document.preferences.android_applications.is_some())
        || (document.schema_version == 2 && document.preferences.manual_mtu.is_some())
        || (document.schema_version < 4
            && document.preferences.routing.mode == TunnelRoutingMode::SelectedApplications)
    {
        return Err(io::Error::other("unsupported preferences version"));
    }
    document.preferences.validated().map_err(io::Error::other)
}

// Read-only migration preserves the original file until an explicit successful save.
// Legacy true armed the firewall, enabled reconnect AND enabled boot services.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyDocument {
    #[serde(rename = "schema_version")]
    _schema_version: u16,
    preferences: LegacyPreferences,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct LegacyPreferences {
    transport: TransportPreference,
    network_profile: NetworkProfile,
    persistent_protection: bool,
    routing: TunnelRoutingPolicy,
}

#[cfg(test)]
mod tests;
