//! Short-lived peers can only echo through the private WireGuard endpoint.
use super::*;
use sirinvpn_protocol::{MeasurementLease, MeasurementLeaseRequest};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Lease {
    device: DeviceId,
    owner_key: String,
    pub public_key: String,
    pub address: Ipv4Addr,
    expires: u64,
    deadline: Instant,
}

impl Lease {
    pub(crate) fn active(&self, document: &AuthorizationDocument, now: u64) -> bool {
        self.expires > now
            && Instant::now() < self.deadline
            && !document.endpoint_transition_source
            && document.devices.iter().any(|device| {
                device.id == self.device
                    && device.wireguard_public_key == self.owner_key
                    && document.access_for_device(device).is_some()
            })
    }
}

pub(super) async fn create(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Json(request): Json<MeasurementLeaseRequest>,
) -> Result<Json<ApiEnvelope<MeasurementLease>>, ApiError> {
    if !state.measurement_ready {
        return Err(ApiError::conflict("isolated measurements are unavailable"));
    }
    validate_wireguard_public_key(&request.public_key)
        .map_err(|_| ApiError::invalid("invalid probe key"))?;
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let authorized = authorize_current(&current, &caller, false)?;
    let device = current
        .devices
        .iter()
        .find(|device| Some(device.id) == authorized.device_id)
        .ok_or_else(ApiError::forbidden)?
        .clone();
    let now = unix_time();
    if current.endpoint_transition_source
        || current
            .desired_peers(now)
            .iter()
            .any(|peer| peer.public_key == request.public_key)
        || current
            .measurement_leases
            .iter()
            .any(|lease| lease.device == device.id && lease.active(&current, now))
    {
        return Err(ApiError::conflict(
            "a measurement is already active or its key is in use",
        ));
    }
    let IpAddr::V4(address) = device.client_tunnel_address else {
        return Err(ApiError::forbidden());
    };
    let address = Ipv4Addr::new(10, 77, 1, address.octets()[3]);
    let lease = Lease {
        device: device.id,
        owner_key: device.wireguard_public_key,
        public_key: request.public_key,
        address,
        expires: now + 120,
        deadline: Instant::now() + Duration::from_secs(120),
    };
    let response = MeasurementLease {
        public_key: lease.public_key.clone(),
        client_address: address,
        expires_at_unix: lease.expires,
    };
    let mut next = current.clone();
    next.measurement_leases
        .retain(|old| old.device != lease.device && old.active(&current, now));
    next.measurement_leases.push(lease);
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(response)))
}

pub(super) async fn remove(
    State(state): State<AppState>,
    Extension(caller): Extension<CallerIdentity>,
    Json(request): Json<MeasurementLeaseRequest>,
) -> Result<Json<ApiEnvelope<()>>, ApiError> {
    let authorization = require_authorization(&state)?;
    let mut current = authorization.write().await;
    let authorized = authorize_current(&current, &caller, false)?;
    let mut next = current.clone();
    next.measurement_leases.retain(|lease| {
        Some(lease.device) != authorized.device_id || lease.public_key != request.public_key
    });
    commit_authorization(&state, &mut current, next).await?;
    Ok(Json(ApiEnvelope::new(())))
}

pub(super) fn quarantine(interface: &str, server: IpAddr) -> String {
    format!(
        concat!(
            "add table inet sirinvpn_measurement\n",
            "add chain inet sirinvpn_measurement input {{ type filter hook input priority -32; policy accept; }}\n",
            "add chain inet sirinvpn_measurement forward {{ type filter hook forward priority -32; policy accept; }}\n",
            "flush chain inet sirinvpn_measurement input\nflush chain inet sirinvpn_measurement forward\n",
            "add rule inet sirinvpn_measurement input iifname \"{interface}\" ip saddr 10.77.1.0/24 ip daddr {server} icmp type echo-request limit rate 20/second burst 40 packets accept\n",
            "add rule inet sirinvpn_measurement input iifname \"{interface}\" ip saddr 10.77.1.0/24 drop\n",
            "add rule inet sirinvpn_measurement forward ip saddr 10.77.1.0/24 drop\n",
            "add rule inet sirinvpn_measurement forward ip daddr 10.77.1.0/24 drop\n",
        ),
        interface = interface,
        server = server
    )
}

pub(super) async fn install(configuration: &ServerConfiguration) -> Result<()> {
    let route = Command::new("ip")
        .args(["-4", "route", "show", "root", "10.77.1.0/24"])
        .output()
        .await?;
    anyhow::ensure!(route.status.success(), "could not inspect probe route");
    if !route.stdout.is_empty() {
        let expected = format!("10.77.1.0/24 dev {}", configuration.interface_name);
        anyhow::ensure!(
            String::from_utf8_lossy(&route.stdout).lines().count() == 1
                && String::from_utf8_lossy(&route.stdout)
                    .split_whitespace()
                    .take(3)
                    .eq(expected.split_whitespace()),
            "measurement subnet is already routed elsewhere"
        );
    }
    // A conflicting private subnet must not acquire our quarantine rules.
    apply_nft_batch(
        &quarantine(
            &configuration.interface_name,
            configuration.server_tunnel_address,
        ),
        "measurement isolation",
    )
    .await?;
    if route.stdout.is_empty() {
        let status = Command::new("ip")
            .args([
                "-4",
                "route",
                "add",
                "10.77.1.0/24",
                "dev",
                &configuration.interface_name,
            ])
            .status()
            .await?;
        anyhow::ensure!(status.success(), "could not install probe route");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn leases_expire_and_follow_revocation_key_rotation_and_restart() {
        let owner = sirinvpn_core::LocalIdentity::generate("Lease owner").unwrap();
        let probe = sirinvpn_core::LocalIdentity::generate("Lease probe").unwrap();
        let mut document = AuthorizationDocument::new_owner(
            ServerId::new(),
            owner.public.wireguard_public_key,
            owner.public.management_certificate_pem,
        )
        .unwrap();
        let lease = Lease {
            device: document.devices[0].id,
            owner_key: document.devices[0].wireguard_public_key.clone(),
            public_key: probe.public.wireguard_public_key,
            address: Ipv4Addr::new(10, 77, 1, 2),
            expires: 220,
            deadline: Instant::now() + Duration::from_secs(120),
        };
        document.measurement_leases.push(lease.clone());
        assert!(lease.active(&document, 100));
        assert!(!lease.active(&document, 220));
        assert_eq!(document.desired_peers(100).len(), 2);
        assert_eq!(document.desired_peers(220).len(), 1);
        let restored: AuthorizationDocument =
            serde_json::from_slice(&serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(restored.measurement_leases.is_empty());
        document.members[0].suspended = true;
        assert!(!lease.active(&document, 100));
        document.members[0].suspended = false;
        document.devices[0].wireguard_public_key = STANDARD.encode([10; 32]);
        assert!(!lease.active(&document, 100));
        document.devices.clear();
        assert!(!lease.active(&document, 100));
    }
    #[test]
    fn quarantine_permits_only_private_echo_and_blocks_forwarding_both_ways() {
        let rules = quarantine("sirinvpn0", "10.77.0.1".parse().unwrap());
        assert!(rules.contains("ip daddr 10.77.0.1 icmp type echo-request"));
        assert!(rules.contains("input iifname \"sirinvpn0\" ip saddr 10.77.1.0/24 drop"));
        assert!(rules.contains("forward ip saddr 10.77.1.0/24 drop"));
        assert!(rules.contains("forward ip daddr 10.77.1.0/24 drop"));
        assert!(!rules.contains("8443"));
    }
}
