//! wireguard-go UAPI text for the Android data tunnel, and the engine's local port.
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sirinvpn_core::SecretIdentity;
use sirinvpn_protocol::TransportKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

/// WireGuard's fixed UDP port whenever a loopback carrier relay may carry the session. The
/// relay accepts datagrams only from `127.0.0.1:` this port and answers only to it, so no
/// other app can inject into or take over the tunnel. Android apps cannot bind ports below
/// 1024 (Linux and the Windows service use 1023 for this), so the port is unprivileged; it
/// sits below Linux's ephemeral range (32768–60999), so no socket gets it by chance. An app
/// that takes it on purpose can only block the connection, which then says so.
pub(crate) const WIREGUARD_LISTEN_PORT: u16 = 31_820;
/// The isolated measurement engine's port, pinned the same way for its probe relay.
pub(crate) const PROBE_LISTEN_PORT: u16 = 31_821;
pub(crate) const PORT_IN_USE: &str = "Another app is using the local port SirinVPN needs (UDP 31820). Close or uninstall the app that uses it, then connect again.";

/// The fixed port when a relay may carry the session: its own carrier, or a later
/// automatic-transport handoff to one. Direct UDP alone keeps an ephemeral port.
pub(crate) fn listen_port(kind: TransportKind, automatic_transport: bool) -> Option<u16> {
    (kind != TransportKind::DirectUdp || automatic_transport).then_some(WIREGUARD_LISTEN_PORT)
}

/// The address a pinned relay admits, for an engine listening on `port`.
pub(crate) fn pinned(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// Whether another socket holds `port` as wireguard-go binds it (`0.0.0.0` and `[::]`).
/// Only meaningful once this process's own engine on that port has stopped.
pub(crate) fn port_taken(port: u16) -> bool {
    let taken = |result: std::io::Result<UdpSocket>| matches!(result, Err(error) if error.kind() == std::io::ErrorKind::AddrInUse);
    taken(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)))
        || taken(UdpSocket::bind((Ipv6Addr::UNSPECIFIED, port)))
}

/// How a refused quality rollback ended. The engine must never keep pointing at a relay
/// that is about to stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Rollback {
    /// The ordinary handoff moved the engine back.
    Restored,
    /// The controller refused it (its phase or task changed); the endpoint was forced back
    /// on the same engine and generation.
    Forced,
    /// Neither applied: the tunnel is rebuilt through the controller's reconnect path.
    Reconnect,
}

/// Tries each way back in order; later ones run only when earlier ones fail.
pub(crate) fn roll_back(
    handoff: impl FnOnce() -> Result<()>,
    force: impl FnOnce() -> Result<()>,
) -> Rollback {
    if handoff().is_ok() {
        Rollback::Restored
    } else if force().is_ok() {
        Rollback::Forced
    } else {
        Rollback::Reconnect
    }
}

/// wireguard-go UAPI settings; keys are hex and the preshared key is peer-scoped.
/// `listen_port` is device-scoped, so it precedes the peer.
pub(crate) fn wireguard_settings(
    secret: &SecretIdentity,
    public: &str,
    endpoint: SocketAddr,
    ipv6_tunnel_enabled: bool,
    listen_port: Option<u16>,
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
        "private_key={}\n{}replace_peers=true\npublic_key={}\n{}endpoint={}\nallowed_ip=0.0.0.0/0\n{}persistent_keepalive_interval=25\n",
        *private,
        listen_port.map_or(String::new(), |port| format!("listen_port={port}\n")),
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
        let legacy = wireguard_settings(&secret, &public, endpoint, false, None).unwrap();
        assert!(!legacy.contains("preshared_key"));
        assert!(!legacy.contains("listen_port"));

        secret.wireguard_preshared_key = Some(STANDARD.encode([5_u8; 32]));
        let settings = wireguard_settings(&secret, &public, endpoint, true, None).unwrap();
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

    #[test]
    fn relay_sessions_fix_the_device_listen_port_before_the_peer() {
        assert_eq!(listen_port(TransportKind::DirectUdp, false), None);
        // An automatic session can hand off to a relay later; that relay pins the same port.
        assert_eq!(
            listen_port(TransportKind::DirectUdp, true),
            Some(WIREGUARD_LISTEN_PORT)
        );
        for kind in [
            TransportKind::ObfuscatedUdp,
            TransportKind::TcpFallback,
            TransportKind::TlsLike,
            TransportKind::Quic,
        ] {
            assert_eq!(listen_port(kind, false), Some(WIREGUARD_LISTEN_PORT));
        }
        const { assert!(WIREGUARD_LISTEN_PORT >= 1024 && PROBE_LISTEN_PORT >= 1024) };
        assert_ne!(WIREGUARD_LISTEN_PORT, PROBE_LISTEN_PORT);
        assert!(PORT_IN_USE.contains(&WIREGUARD_LISTEN_PORT.to_string()));
        assert_eq!(pinned(31_820), SocketAddr::from(([127, 0, 0, 1], 31_820)));

        let secret = sirinvpn_core::LocalIdentity::generate("Android")
            .unwrap()
            .secret;
        let endpoint = SocketAddr::from(([127, 0, 0, 1], 51_821));
        let settings = wireguard_settings(&secret, "00", endpoint, false, Some(31_820)).unwrap();
        let lines: Vec<_> = settings.lines().collect();
        let port = lines
            .iter()
            .position(|l| *l == "listen_port=31820")
            .unwrap();
        let peer = lines
            .iter()
            .position(|l| l.starts_with("public_key="))
            .unwrap();
        assert!(port < peer, "listen_port is a device key, not a peer key");
    }

    #[test]
    fn a_port_held_by_another_socket_is_reported_taken() {
        let holder = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = holder.local_addr().unwrap().port();
        assert!(port_taken(port));
        drop(holder);
        assert!(!port_taken(port));
    }

    #[test]
    fn rollback_forces_then_reconnects_and_stops_at_the_first_success() {
        let ok = || Ok(());
        let refused = || Err(anyhow::anyhow!("refused"));
        assert_eq!(
            roll_back(ok, || panic!("no force after a rollback")),
            Rollback::Restored
        );
        assert_eq!(roll_back(refused, ok), Rollback::Forced);
        assert_eq!(roll_back(refused, refused), Rollback::Reconnect);
    }
}
