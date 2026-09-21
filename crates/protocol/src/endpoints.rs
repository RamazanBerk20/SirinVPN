//! Current public contact information. Previous information is retained only while
//! a signed handoff is current; this is not a connection or activity history.
use super::*;

pub const MAX_ALTERNATE_ENDPOINT_HOSTS: usize = 3;

pub fn valid_alternate_endpoint_hosts(primary: &str, alternatives: &[String]) -> bool {
    alternatives.len() <= MAX_ALTERNATE_ENDPOINT_HOSTS
        && alternatives.iter().enumerate().all(|(index, host)| {
            validate_host(host).is_ok()
                && host.trim() == host
                && host == &host.to_ascii_lowercase()
                && !host.eq_ignore_ascii_case(primary)
                && !alternatives[..index].contains(host)
        })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointDescriptor {
    pub endpoint: ServerEndpoint,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternate_endpoint_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_discovery_port: Option<u16>,
    pub ipv6_tunnel_enabled: bool,
    pub obfuscated_udp: Option<ObfuscatedUdpEndpoint>,
    pub tcp_fallback: Option<TcpFallbackEndpoint>,
    pub tls_like: Option<TlsLikeEndpoint>,
}

/// Immutable server pins plus the latest accepted public checkpoint. This is
/// sufficient for a privileged reconnect service; it contains no device secret.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointIdentity {
    pub server_id: ServerId,
    pub server_wireguard_public_key: String,
    pub pinned_server_certificate_pem: String,
    pub generation: u64,
    pub descriptor: EndpointDescriptor,
}

impl ServerProfile {
    pub fn endpoint_identity(&self) -> EndpointIdentity {
        EndpointIdentity {
            server_id: self.id,
            server_wireguard_public_key: self.server_wireguard_public_key.clone(),
            pinned_server_certificate_pem: self.pinned_server_certificate_pem.clone(),
            generation: self.endpoint_generation,
            descriptor: self.endpoint_descriptor(),
        }
    }
    pub fn endpoint_descriptor(&self) -> EndpointDescriptor {
        EndpointDescriptor {
            endpoint: self.endpoint.clone(),
            alternate_endpoint_hosts: self.alternate_endpoint_hosts.clone(),
            endpoint_discovery_port: self.endpoint_discovery_port,
            ipv6_tunnel_enabled: self.ipv6_tunnel_enabled,
            obfuscated_udp: self.obfuscated_udp.clone(),
            tcp_fallback: self.tcp_fallback.clone(),
            tls_like: self.tls_like.clone(),
        }
    }

    pub fn set_endpoint_descriptor(&mut self, descriptor: &EndpointDescriptor) {
        self.endpoint = descriptor.endpoint.clone();
        self.alternate_endpoint_hosts = descriptor.alternate_endpoint_hosts.clone();
        self.endpoint_discovery_port = descriptor.endpoint_discovery_port;
        self.ipv6_tunnel_enabled = descriptor.ipv6_tunnel_enabled;
        self.obfuscated_udp = descriptor.obfuscated_udp.clone();
        self.tcp_fallback = descriptor.tcp_fallback.clone();
        self.tls_like = descriptor.tls_like.clone();
    }
}

impl EndpointTransitionClaims {
    pub fn endpoint_descriptor(&self) -> EndpointDescriptor {
        EndpointDescriptor {
            endpoint: self.endpoint.clone(),
            alternate_endpoint_hosts: self.alternate_endpoint_hosts.clone(),
            endpoint_discovery_port: self.endpoint_discovery_port,
            ipv6_tunnel_enabled: self.ipv6_tunnel_enabled,
            obfuscated_udp: self.obfuscated_udp.clone(),
            tcp_fallback: self.tcp_fallback.clone(),
            tls_like: self.tls_like.clone(),
        }
    }
}

impl InvitationClaims {
    pub fn required_schema_version(&self) -> u16 {
        if !self.alternate_endpoint_hosts.is_empty() || self.endpoint_discovery_port.is_some() {
            3
        } else if self.max_uses != 1 || !self.member_policy.is_default() {
            2
        } else {
            1
        }
    }
}

impl RecoveryKeyClaims {
    pub fn required_schema_version(&self) -> u16 {
        if !self.alternate_endpoint_hosts.is_empty() || self.endpoint_discovery_port.is_some() {
            2
        } else {
            1
        }
    }
}
