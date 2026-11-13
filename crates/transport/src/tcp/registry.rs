use super::*;

/// A device's newest proven connections win, as on QUIC. A roaming device leaves
/// connections that black-hole without a FIN; refusing the newest one would lock it out of
/// every stream carrier until the idle timeout, so the oldest is ended instead. A completed
/// handshake is not enough to take a slot: a replayed initiator message completes one too.
/// A connection counts, and may end another, only once its first record from the client
/// decrypted. That needs the session keys, which need the client's ephemeral and static
/// private keys of this exchange (Noise IK `ee` and `se` against the server's fresh
/// ephemeral), so a replay never gets there. Until then it holds no slot and ends nothing;
/// the idle timeout closes it if it never proves.
#[derive(Clone, Default)]
pub(super) struct ClientConnectionRegistry(pub(super) Arc<Mutex<ClientConnections>>);

#[derive(Default)]
pub(super) struct ClientConnections {
    next_id: u64,
    pub(super) devices: HashMap<[u8; 32], VecDeque<(u64, oneshot::Sender<()>)>>,
}

impl ClientConnectionRegistry {
    /// A permit for a connection that has not proven the device key yet.
    pub(super) fn acquire(&self, peer: [u8; 32]) -> (ClientConnectionPermit, Eviction) {
        let (sender, evicted) = oneshot::channel();
        let mut connections = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let id = connections.next_id;
        connections.next_id = id.wrapping_add(1);
        (
            ClientConnectionPermit {
                registry: self.clone(),
                peer,
                id,
                unproven: Mutex::new(Some(sender)),
            },
            Eviction(evicted),
        )
    }
}

pub(super) struct ClientConnectionPermit {
    registry: ClientConnectionRegistry,
    peer: [u8; 32],
    id: u64,
    /// Held here, so `Eviction` cannot fire, until the connection proves the device key.
    unproven: Mutex<Option<oneshot::Sender<()>>>,
}

impl ClientConnectionPermit {
    /// Takes a slot once the connection proved the device key, ending the device's
    /// oldest proven connection if all slots are taken.
    pub(super) fn prove(&self) {
        let Some(sender) = lock(&self.unproven).take() else {
            return;
        };
        let mut connections = lock(&self.registry.0);
        let current = connections.devices.entry(self.peer).or_default();
        current.push_back((self.id, sender));
        while current.len() > MAX_CONNECTIONS_PER_CLIENT {
            if let Some((_, oldest)) = current.pop_front() {
                let _ = oldest.send(());
            }
        }
    }
}

pub(super) struct Eviction(oneshot::Receiver<()>);

impl Eviction {
    /// Resolves once a newer proven connection from the same device took this one's slot.
    pub(super) async fn evicted(&mut self) {
        let _ = (&mut self.0).await;
    }
}

impl Drop for ClientConnectionPermit {
    fn drop(&mut self) {
        let mut connections = self
            .registry
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(current) = connections.devices.get_mut(&self.peer) {
            current.retain(|(id, _)| *id != self.id);
            if current.is_empty() {
                connections.devices.remove(&self.peer);
            }
        }
    }
}
