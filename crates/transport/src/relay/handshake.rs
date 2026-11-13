use super::*;

/// Client handshakes start their encrypted payload with this marker and a wall-clock
/// timestamp. Older servers never read the payload and older clients send only random
/// padding, so both directions stay compatible.
pub(super) const HANDSHAKE_TIMESTAMP_MARKER: [u8; 8] = *b"SVPNts01";
const HANDSHAKE_TIMESTAMP_LENGTH: usize = HANDSHAKE_TIMESTAMP_MARKER.len() + 12;
/// Concurrent carriers and quality probes from one client can arrive out of order.
const HANDSHAKE_TIMESTAMP_TOLERANCE: Duration = Duration::from_secs(10);
/// After a server restart, a handshake captured earlier than this is refused. It is a
/// full day because a client clock that lags by more cannot use any Noise carrier: a
/// dual-boot RTC in local time is hours off, and with the kill switch on NTP may be
/// unreachable until the tunnel is up. The same bound applies to timestamps ahead of this
/// clock, so a future-stamped capture cannot stay replayable for longer.
pub(super) const HANDSHAKE_MAX_AGE: Duration = Duration::from_secs(24 * 3_600);

/// Why the replay cache refused a tunnel handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandshakeRefusal {
    /// The same message, an older one than this client already used, or an unmarked
    /// one from a client that sends timestamps.
    Replayed,
    /// Timestamped more than `HANDSHAKE_MAX_AGE` before this server's clock: a replay
    /// captured long ago, or a client clock that is far behind.
    TimestampTooOld { age: Duration },
    /// Timestamped more than `HANDSHAKE_MAX_AGE` after this server's clock: a client
    /// clock that is far ahead, or a capture of one.
    TimestampTooFarAhead { ahead: Duration },
}

/// Clock refusals go to the server's log (stderr, the journal) so a client with a far
/// wrong clock can be diagnosed. At most one line a minute: replays must not flood it.
fn log_refusal(refusal: HandshakeRefusal) {
    static LAST_LOGGED: AtomicU64 = AtomicU64::new(0);
    let (offset, direction, clock) = match refusal {
        HandshakeRefusal::TimestampTooOld { age } => (age, "before", "behind"),
        HandshakeRefusal::TimestampTooFarAhead { ahead } => (ahead, "after", "ahead"),
        HandshakeRefusal::Replayed => return,
    };
    let now = unix_now().as_secs();
    let last = LAST_LOGGED.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= 60
        && LAST_LOGGED
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        eprintln!(
            "sirinvpn: refused a carrier handshake timestamped {} s {direction} this server's \
             clock (a replayed capture, or a client clock more than 24 h {clock})",
            offset.as_secs()
        );
    }
}

pub(super) fn unix_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// Where a carrier that has a channel secret (QUIC's TLS exporter) puts it in the
/// initiator payload. Older servers read only the timestamp and ignore it.
const HANDSHAKE_BINDING: std::ops::Range<usize> =
    HANDSHAKE_TIMESTAMP_LENGTH..HANDSHAKE_TIMESTAMP_LENGTH + 32;

/// Like `client_handshake_payload`, binding the handshake to one outer connection. Only the
/// device key can write this payload (Noise IK encrypts it under `ss`), so a server that
/// finds its own connection's secret here knows the device made this message for it.
pub(crate) fn client_handshake_payload_bound(binding: &[u8; 32]) -> Vec<u8> {
    let mut payload = client_handshake_payload();
    payload.resize(payload.len().max(HANDSHAKE_BINDING.end), 0);
    payload[HANDSHAKE_BINDING].copy_from_slice(binding);
    payload
}

/// Whether an initiator payload carries `binding`; random padding of older clients never does.
pub(crate) fn handshake_is_bound(payload: &[u8], binding: &[u8; 32]) -> bool {
    payload.get(HANDSHAKE_BINDING) == Some(binding.as_slice())
}

/// The first initiator payload: a timestamp followed by random padding.
pub(crate) fn client_handshake_payload() -> Vec<u8> {
    let mut payload = random_bytes(OsRng.gen_range(48..=144));
    let now = unix_now();
    payload[..HANDSHAKE_TIMESTAMP_MARKER.len()].copy_from_slice(&HANDSHAKE_TIMESTAMP_MARKER);
    payload[8..16].copy_from_slice(&now.as_secs().to_be_bytes());
    payload[16..HANDSHAKE_TIMESTAMP_LENGTH].copy_from_slice(&now.subsec_nanos().to_be_bytes());
    payload
}

pub(super) fn handshake_timestamp(payload: &[u8]) -> Option<Duration> {
    let rest = payload.strip_prefix(&HANDSHAKE_TIMESTAMP_MARKER)?;
    let seconds = u64::from_be_bytes(rest.get(..8)?.try_into().ok()?);
    let nanos = u32::from_be_bytes(rest.get(8..12)?.try_into().ok()?);
    (nanos < 1_000_000_000).then(|| Duration::new(seconds, nanos))
}

/// Rejects repeated handshake messages, and older handshakes from a client that has
/// since sent a newer one. Digests are kept for 180 s past the later of arrival and the
/// message's timestamp, and all of it is lost on restart, so an accepted handshake proves
/// nothing by itself: carriers let a connection displace another only after it proved the
/// device key in its own exchange.
#[derive(Default)]
pub(crate) struct HandshakeReplayCache {
    /// Expiry and digest, earliest expiry first.
    entries: BTreeSet<(Instant, [u8; 32])>,
    digests: HashSet<[u8; 32]>,
    /// Newest accepted timestamp per authorized client key, clamped to this server's
    /// clock so a client whose clock ran ahead is not locked out once it is corrected.
    latest: HashMap<[u8; 32], Duration>,
}

impl HandshakeReplayCache {
    /// For tunnel handshakes whose initiator payload came from `client_handshake_payload`.
    pub(crate) fn accept_client_handshake(
        &mut self,
        message: &[u8],
        client_static: [u8; 32],
        payload: &[u8],
    ) -> Result<(), HandshakeRefusal> {
        let result = self.check_client_handshake(message, client_static, payload, Instant::now());
        if let Err(refusal) = result {
            log_refusal(refusal);
        }
        result
    }

    pub(super) fn check_client_handshake(
        &mut self,
        message: &[u8],
        client_static: [u8; 32],
        payload: &[u8],
        now: Instant,
    ) -> Result<(), HandshakeRefusal> {
        let timestamp = handshake_timestamp(payload);
        let clock = unix_now();
        // `latest` is lost on restart; the server clock bounds how old a replay can be.
        if let Some(age) = timestamp
            .and_then(|timestamp| clock.checked_sub(timestamp))
            .filter(|age| *age > HANDSHAKE_MAX_AGE)
        {
            return Err(HandshakeRefusal::TimestampTooOld { age });
        }
        let ahead = timestamp
            .and_then(|timestamp| timestamp.checked_sub(clock))
            .unwrap_or_default();
        if ahead > HANDSHAKE_MAX_AGE {
            return Err(HandshakeRefusal::TimestampTooFarAhead { ahead });
        }
        match (timestamp, self.latest.get(&client_static)) {
            // A client that sends timestamps never sends an unmarked handshake again.
            (None, Some(_)) => return Err(HandshakeRefusal::Replayed),
            (Some(timestamp), Some(latest))
                if timestamp.saturating_add(HANDSHAKE_TIMESTAMP_TOLERANCE) <= *latest =>
            {
                return Err(HandshakeRefusal::Replayed);
            }
            _ => {}
        }
        // A future stamp stays fresh until the server clock passes it, so its digest must too.
        if !self.insert_until(message, now, now + ahead + SESSION_IDLE_TIMEOUT) {
            return Err(HandshakeRefusal::Replayed);
        }
        if let Some(timestamp) = timestamp {
            let latest = self.latest.entry(client_static).or_default();
            *latest = (*latest).max(timestamp.min(clock));
        }
        Ok(())
    }

    pub(crate) fn insert_once(&mut self, message: &[u8]) -> bool {
        let now = Instant::now();
        self.insert_until(message, now, now + SESSION_IDLE_TIMEOUT)
    }

    pub(super) fn insert_until(&mut self, message: &[u8], now: Instant, expiry: Instant) -> bool {
        // Expired entries go first; a full cache then drops the one closest to expiry.
        while let Some(&(first, digest)) = self.entries.first()
            && (first < now || self.entries.len() >= 4_096)
        {
            self.entries.remove(&(first, digest));
            self.digests.remove(&digest);
        }
        let digest: [u8; 32] = Sha256::digest(message).into();
        if !self.digests.insert(digest) {
            return false;
        }
        self.entries.insert((expiry, digest));
        true
    }
}

/// Bounds handshake attempts per source, and in total, before any Noise work is done.
#[derive(Default)]
pub(crate) struct ProbeLimiter {
    pub(super) peers: HashMap<IpAddr, ProbeWindow>,
    pub(super) global: Option<ProbeWindow>,
}

pub(super) struct ProbeWindow {
    started: Instant,
    attempts: u16,
}

pub(super) const PROBE_SOURCES: usize = 1_024;
pub(super) const PROBE_ATTEMPTS_PER_SOURCE: u16 = 12;
const PROBE_ATTEMPTS_PER_SECOND: u16 = 1_024;

/// IPv6 sources are limited per /64, which one subscriber can occupy entirely.
fn probe_source(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(mapped) => IpAddr::V4(mapped),
            None => {
                let segments = address.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(
                    segments[0],
                    segments[1],
                    segments[2],
                    segments[3],
                    0,
                    0,
                    0,
                    0,
                ))
            }
        },
        address => address,
    }
}

impl ProbeLimiter {
    pub(crate) fn allow(&mut self, address: IpAddr) -> bool {
        self.allow_source(Some(probe_source(address)))
    }

    /// Behind a CDN every source is a shared CDN edge that anyone can make connect,
    /// so a per-source budget would let one client lock out everyone at that edge.
    pub(crate) fn allow_global(&mut self) -> bool {
        self.allow_source(None)
    }

    fn allow_source(&mut self, address: Option<IpAddr>) -> bool {
        if let Some(address) = address
            && self.peers.len() >= PROBE_SOURCES
            && !self.peers.contains_key(&address)
        {
            self.peers
                .retain(|_, window| window.started.elapsed() < Duration::from_secs(60));
            // A full table must not lock every new source out: replace the oldest window and
            // rely on the global budget below to bound the work a flood can cause.
            if self.peers.len() >= PROBE_SOURCES
                && let Some(oldest) = self
                    .peers
                    .iter()
                    .min_by_key(|(_, window)| window.started)
                    .map(|(address, _)| *address)
            {
                self.peers.remove(&oldest);
            }
        }
        let global = self.global.get_or_insert(ProbeWindow {
            started: Instant::now(),
            attempts: 0,
        });
        if global.started.elapsed() >= Duration::from_secs(1) {
            global.started = Instant::now();
            global.attempts = 0;
        }
        if global.attempts >= PROBE_ATTEMPTS_PER_SECOND {
            return false;
        }
        if let Some(address) = address {
            let window = self.peers.entry(address).or_insert(ProbeWindow {
                started: Instant::now(),
                attempts: 0,
            });
            if window.started.elapsed() >= Duration::from_secs(10) {
                window.started = Instant::now();
                window.attempts = 0;
            }
            if window.attempts >= PROBE_ATTEMPTS_PER_SOURCE {
                return false;
            }
            window.attempts += 1;
        }
        global.attempts += 1;
        true
    }
}
