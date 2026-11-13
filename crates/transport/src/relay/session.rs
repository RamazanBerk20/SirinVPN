//! Client-side relay state shared by every carrier: who may speak for WireGuard on the
//! loopback socket, and whether an authenticated carrier still delivers anything.
use super::*;

/// The loopback address WireGuard sends from, and the only one replies go to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalPeer {
    /// The caller fixed WireGuard's listen port and every other source is dropped. That
    /// stops other local processes only if they cannot bind the port first: on Linux the
    /// 1023 pin is below the default unprivileged-port floor (`ip_unprivileged_port_start`
    /// = 1024), so only root can. Windows has no privileged ports and Android's pin is
    /// above 1024, so there a local squatter that binds first can still block WireGuard
    /// or receive the relay's (WireGuard-encrypted) packets: the pin narrows, not prevents.
    Pinned(SocketAddr),
    /// shortcut: callers that do not fix WireGuard's port learn the latest loopback
    /// sender, which any local process can take over; upgrade by passing a pinned port.
    Learned(Option<SocketAddr>),
}

impl LocalPeer {
    pub(crate) fn new(pinned: Option<SocketAddr>) -> Result<Self, RelayError> {
        match pinned {
            Some(peer) if !peer.ip().is_loopback() || peer.port() == 0 => {
                Err(RelayError::InvalidConfiguration)
            }
            Some(peer) => Ok(Self::Pinned(peer)),
            None => Ok(Self::Learned(None)),
        }
    }

    /// Whether a datagram from `source` is WireGuard's. A learned peer follows it.
    pub(crate) fn admit(&mut self, source: SocketAddr) -> bool {
        match self {
            Self::Pinned(peer) => *peer == source,
            Self::Learned(peer) => {
                if !source.ip().is_loopback() {
                    return false;
                }
                *peer = Some(source);
                true
            }
        }
    }

    /// Where decrypted server packets go; nowhere until a learned peer has spoken.
    pub(crate) fn target(&self) -> Option<SocketAddr> {
        match self {
            Self::Pinned(peer) => Some(*peer),
            Self::Learned(peer) => *peer,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CarrierPhase {
    Up,
    /// WireGuard keeps sending but nothing authenticated came back for a while: the
    /// carrier is half-open. UDP re-handshakes; stream carriers end so they reconnect.
    Stale,
}

/// An authenticated carrier session after its handshake.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CarrierSession {
    last_rx: Instant,
    last_tx: Instant,
}

impl CarrierSession {
    pub(crate) fn established() -> Self {
        let now = Instant::now();
        Self {
            last_rx: now,
            last_tx: now,
        }
    }

    pub(crate) fn received(&mut self) {
        self.last_rx = Instant::now();
    }

    pub(crate) fn sent(&mut self) {
        self.last_tx = Instant::now();
    }

    pub(crate) fn phase(&self) -> CarrierPhase {
        if self.last_rx.elapsed() >= CLIENT_REHANDSHAKE_AFTER
            && self.last_tx.elapsed() < CLIENT_REHANDSHAKE_AFTER
        {
            CarrierPhase::Stale
        } else {
            CarrierPhase::Up
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pinned_peer_admits_only_wireguard_and_never_moves() {
        let wireguard: SocketAddr = "127.0.0.1:1023".parse().unwrap();
        let mut peer = LocalPeer::new(Some(wireguard)).unwrap();
        assert!(!peer.admit("127.0.0.1:40000".parse().unwrap()));
        assert!(!peer.admit("127.0.0.2:1023".parse().unwrap()));
        assert_eq!(peer.target(), Some(wireguard));
        assert!(peer.admit(wireguard));
        assert!(LocalPeer::new(Some("192.0.2.1:1023".parse().unwrap())).is_err());
        assert!(LocalPeer::new(Some("127.0.0.1:0".parse().unwrap())).is_err());
    }

    #[test]
    fn a_learned_peer_follows_the_latest_loopback_sender() {
        let mut peer = LocalPeer::new(None).unwrap();
        assert_eq!(peer.target(), None);
        assert!(!peer.admit("192.0.2.1:5000".parse().unwrap()));
        assert!(peer.admit("127.0.0.1:5000".parse().unwrap()));
        assert!(peer.admit("127.0.0.1:6000".parse().unwrap()));
        assert_eq!(peer.target(), Some("127.0.0.1:6000".parse().unwrap()));
    }

    #[test]
    fn a_carrier_is_stale_only_while_wireguard_still_sends() {
        let mut session = CarrierSession::established();
        assert_eq!(session.phase(), CarrierPhase::Up);
        session.last_rx -= CLIENT_REHANDSHAKE_AFTER;
        assert_eq!(session.phase(), CarrierPhase::Stale);
        session.last_tx -= CLIENT_REHANDSHAKE_AFTER;
        assert_eq!(session.phase(), CarrierPhase::Up);
        session.received();
        session.sent();
        assert_eq!(session.phase(), CarrierPhase::Up);
    }
}
