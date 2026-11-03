//! Each device's reported platform, used only for its icon. It lives in its own file beside
//! the authorization document, so recording one never runs an authorization commit
//! (containment, WireGuard, recovery). Older servers never read the file, and losing it
//! only loses icons until each app reports again.

use super::*;
use sirinvpn_protocol::DEVICE_PLATFORMS;

const FILE_NAME: &str = "device-platforms.json";
/// Far above one short entry per possible device; a larger file reads as empty.
const MAX_BYTES: usize = 64 * 1024;

fn path(authorization: &Path) -> std::path::PathBuf {
    authorization.with_file_name(FILE_NAME)
}

/// A missing, oversized or unreadable file reads as no platforms, and unknown values are dropped.
pub(super) fn load(authorization: &Path) -> HashMap<DeviceId, String> {
    sirinvpn_platform::files::read_bounded(&path(authorization), MAX_BYTES)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<HashMap<DeviceId, String>>(&bytes).ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, platform)| DEVICE_PLATFORMS.contains(&platform.as_str()))
        .collect()
}

impl AuthorizationDocument {
    /// Writes the platforms file, keeping only current devices, then updates memory.
    /// Nothing else in the document changes and nothing reaches the network.
    pub(crate) fn record_device_platform(
        &mut self,
        authorization: &Path,
        device: DeviceId,
        platform: &str,
    ) -> Result<()> {
        if !DEVICE_PLATFORMS.contains(&platform) || !self.devices.iter().any(|d| d.id == device) {
            bail!("the device platform is not supported");
        }
        if self.device_platforms.get(&device).map(String::as_str) == Some(platform) {
            return Ok(());
        }
        let mut platforms = self.device_platforms.clone();
        platforms.retain(|id, _| self.devices.iter().any(|d| d.id == *id));
        platforms.insert(device, platform.to_owned());
        sirinvpn_platform::files::atomic_write(
            &path(authorization),
            &serde_json::to_vec(&platforms)?,
            true,
        )?;
        self.device_platforms = platforms;
        Ok(())
    }
}
