//! wireguard-go UAPI text for the Android data tunnel.
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sirinvpn_core::SecretIdentity;
use std::net::SocketAddr;

/// wireguard-go UAPI settings; keys are hex and the preshared key is peer-scoped.
pub(crate) fn wireguard_settings(
    secret: &SecretIdentity,
    public: &str,
    endpoint: SocketAddr,
    ipv6_tunnel_enabled: bool,
) -> Result<zeroize::Zeroizing<String>> {
    let hex_key = |key: &str| -> Result<zeroize::Zeroizing<String>> {
        let bytes = zeroize::Zeroizing::new(STANDARD.decode(key)?);
        Ok(zeroize::Zeroizing::new(hex::encode(bytes.as_slice())))
    };
    let private = hex_key(&secret.wireguard_private_key)?;
    let preshared = match &secret.wireguard_preshared_key {
        Some(key) => zeroize::Zeroizing::new(format!("preshared_key={}\n", *hex_key(key)?)),
        None => zeroize::Zeroizing::new(String::new()),
    };
    Ok(zeroize::Zeroizing::new(format!(
        "private_key={}\nreplace_peers=true\npublic_key={}\n{}endpoint={}\nallowed_ip=0.0.0.0/0\n{}persistent_keepalive_interval=25\n",
        *private,
        public,
        *preshared,
        endpoint,
        if ipv6_tunnel_enabled {
            "allowed_ip=::/0\n"
        } else {
            ""
        }
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uapi_settings_carry_the_preshared_key_on_the_server_peer() {
        let mut secret = sirinvpn_core::LocalIdentity::generate("Android")
            .unwrap()
            .secret;
        let endpoint = SocketAddr::from(([127, 0, 0, 1], 51_820));
        let public = hex::encode([8_u8; 32]);
        let legacy = wireguard_settings(&secret, &public, endpoint, false).unwrap();
        assert!(!legacy.contains("preshared_key"));

        secret.wireguard_preshared_key = Some(STANDARD.encode([5_u8; 32]));
        let settings = wireguard_settings(&secret, &public, endpoint, true).unwrap();
        let lines: Vec<_> = settings.lines().collect();
        let peer = lines
            .iter()
            .position(|line| line.starts_with("public_key="))
            .unwrap();
        assert_eq!(
            lines[peer + 1],
            format!("preshared_key={}", hex::encode([5_u8; 32]))
        );
        assert!(lines.contains(&"allowed_ip=::/0"));
        assert!(!settings.contains(&STANDARD.encode([5_u8; 32])));
    }
}
