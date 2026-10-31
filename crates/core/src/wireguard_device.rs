//! A device that joins through a standard WireGuard configuration, such as the
//! official iOS/macOS apps or a router. It has no management identity.

use crate::generate_preshared_key;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::rngs::OsRng;
use sirinvpn_protocol::{
    DeviceSummary, MemberId, MemberPolicy, ServerProfile, WireGuardDeviceCreateRequest,
    ipv6_tunnel_address, validate_host, validate_server_name,
};
use std::{
    net::{IpAddr, Ipv6Addr},
    path::Path,
};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Error)]
pub enum WireGuardDeviceError {
    #[error("the WireGuard device details are invalid")]
    InvalidInput,
    #[error("the server response does not match the requested WireGuard device")]
    ResponseMismatch,
}

/// Keys exist only on this device; the VPS receives the public key and preshared key.
pub struct WireGuardDeviceDraft {
    request: WireGuardDeviceCreateRequest,
    private_key: StaticSecret,
    profile: ServerProfile,
}

impl Drop for WireGuardDeviceDraft {
    fn drop(&mut self) {
        self.request.preshared_key.zeroize();
    }
}

/// The only copy of the device's private key; it is shown once and never stored.
pub struct WireGuardDeviceConfig {
    text: Zeroizing<String>,
    file_name: String,
    device: DeviceSummary,
}

impl std::fmt::Debug for WireGuardDeviceConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WireGuardDeviceConfig")
            .field("text", &"[REDACTED]")
            .field("file_name", &self.file_name)
            .field("device", &self.device)
            .finish()
    }
}

impl WireGuardDeviceDraft {
    pub fn new(
        profile: &ServerProfile,
        member_name: &str,
        device_name: &str,
        target_member_id: Option<MemberId>,
        member_policy: MemberPolicy,
    ) -> Result<Self, WireGuardDeviceError> {
        validate_server_name(member_name).map_err(|_| WireGuardDeviceError::InvalidInput)?;
        validate_server_name(device_name).map_err(|_| WireGuardDeviceError::InvalidInput)?;
        validate_host(&profile.endpoint.host).map_err(|_| WireGuardDeviceError::InvalidInput)?;
        if member_policy.validate().is_err()
            || (target_member_id.is_some() && !member_policy.is_default())
        {
            return Err(WireGuardDeviceError::InvalidInput);
        }
        let private_key = StaticSecret::random_from_rng(OsRng);
        let request = WireGuardDeviceCreateRequest {
            server_id: profile.id,
            endpoint: profile.endpoint.clone(),
            member_name: member_name.trim().to_owned(),
            device_name: device_name.trim().to_owned(),
            target_member_id,
            member_policy,
            wireguard_public_key: STANDARD.encode(PublicKey::from(&private_key).as_bytes()),
            preshared_key: generate_preshared_key(),
        };
        Ok(Self {
            request,
            private_key,
            profile: profile.clone(),
        })
    }

    pub fn request(&self) -> &WireGuardDeviceCreateRequest {
        &self.request
    }

    pub fn finish(
        self,
        device: DeviceSummary,
    ) -> Result<WireGuardDeviceConfig, WireGuardDeviceError> {
        let IpAddr::V4(address) = device.client_tunnel_address else {
            return Err(WireGuardDeviceError::ResponseMismatch);
        };
        let [10, 77, 0, host] = address.octets() else {
            return Err(WireGuardDeviceError::ResponseMismatch);
        };
        if !device.wireguard_only
            || !(3..=223).contains(&host)
            || device.name != self.request.device_name
            || self
                .request
                .target_member_id
                .is_some_and(|member_id| member_id != device.member_id)
        {
            return Err(WireGuardDeviceError::ResponseMismatch);
        }
        let mut addresses = format!("{address}/32");
        if self.profile.ipv6_tunnel_enabled {
            let ipv6 = ipv6_tunnel_address(self.profile.id, address)
                .ok_or(WireGuardDeviceError::ResponseMismatch)?;
            addresses.push_str(&format!(", {ipv6}/128"));
        }
        let host = &self.profile.endpoint.host;
        let endpoint = if host.parse::<Ipv6Addr>().is_ok() {
            format!("[{host}]:{}", self.profile.endpoint.wireguard_port)
        } else {
            format!("{host}:{}", self.profile.endpoint.wireguard_port)
        };
        let private_key = Zeroizing::new(STANDARD.encode(self.private_key.to_bytes()));
        // ::/0 even without tunnel IPv6, so IPv6 traffic cannot bypass the tunnel.
        let text = Zeroizing::new(format!(
            "[Interface]\nPrivateKey = {}\nAddress = {addresses}\nDNS = {}\n\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nEndpoint = {endpoint}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
            private_key.as_str(),
            self.profile.server_tunnel_address,
            self.profile.server_wireguard_public_key,
            self.request.preshared_key,
        ));
        Ok(WireGuardDeviceConfig {
            text,
            file_name: config_file_name(&device.name),
            device,
        })
    }
}

impl WireGuardDeviceConfig {
    pub fn expose(&self) -> &str {
        self.text.as_str()
    }

    /// wg-quick and the WireGuard apps take the tunnel name from the file name.
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    pub fn device(&self) -> &DeviceSummary {
        &self.device
    }

    /// Mode 0600 and never replaces an existing file.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        sirinvpn_platform::files::atomic_write(path, self.text.as_bytes(), false)
    }
}

/// Interface names allow 15 characters from this set on Linux.
fn config_file_name(device_name: &str) -> String {
    let name: String = device_name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || "_=+.-".contains(character) {
                character
            } else {
                '-'
            }
        })
        .collect();
    let name: String = name.trim_matches(['-', '.']).chars().take(15).collect();
    format!("{}.conf", if name.is_empty() { "sirinvpn" } else { &name })
}

#[cfg(test)]
mod tests;
