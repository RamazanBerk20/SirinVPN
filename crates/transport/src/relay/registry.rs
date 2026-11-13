use super::*;

pub(super) type TransportActivity = HashMap<[u8; 32], (TransportKind, Instant, u64)>;

#[derive(Default)]
pub(super) struct TransportActivityState {
    entries: RwLock<TransportActivity>,
    next_connection_id: AtomicU64,
}

#[derive(Clone, Default)]
pub struct ActiveTransportRegistry(Arc<TransportActivityState>);

pub(crate) struct ActiveTransportConnection {
    registry: ActiveTransportRegistry,
    peer: [u8; 32],
    transport: TransportKind,
    connection_id: u64,
}

impl ActiveTransportRegistry {
    pub(crate) fn record(&self, peer: [u8; 32], transport: TransportKind) {
        self.0
            .entries
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(peer, (transport, Instant::now(), 0));
    }

    pub(crate) fn connection(
        &self,
        peer: [u8; 32],
        transport: TransportKind,
    ) -> ActiveTransportConnection {
        let connection_id = loop {
            let candidate = self
                .0
                .next_connection_id
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1);
            if candidate != 0 {
                break candidate;
            }
        };
        let connection = ActiveTransportConnection {
            registry: self.clone(),
            peer,
            transport,
            connection_id,
        };
        connection.record();
        connection
    }

    pub fn is_obfuscated_recent(&self, peer: &[u8; 32], maximum_age: Duration) -> bool {
        self.recent_transport(peer, maximum_age) == Some(TransportKind::ObfuscatedUdp)
    }

    pub fn recent_transport(
        &self,
        peer: &[u8; 32],
        maximum_age: Duration,
    ) -> Option<TransportKind> {
        self.0
            .entries
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(peer)
            .and_then(|(transport, seen, _)| (seen.elapsed() <= maximum_age).then_some(*transport))
    }

    pub(crate) fn prune(&self, maximum_age: Duration) {
        self.0
            .entries
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|_, (_, seen, _)| seen.elapsed() <= maximum_age);
    }
}

impl ActiveTransportConnection {
    pub(crate) fn record(&self) {
        self.registry
            .0
            .entries
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                self.peer,
                (self.transport, Instant::now(), self.connection_id),
            );
    }
}

impl Drop for ActiveTransportConnection {
    fn drop(&mut self) {
        let mut entries = self
            .registry
            .0
            .entries
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if entries
            .get(&self.peer)
            .is_some_and(|(_, _, connection_id)| *connection_id == self.connection_id)
        {
            entries.remove(&self.peer);
        }
    }
}
