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

impl EndpointDescriptor {
    /// The HTTPS hostname devices reach through a CDN, when CDN mode is on.
    pub fn cdn_host(&self) -> Option<&str> {
        let https = self.tls_like.as_ref()?.https.as_ref()?;
        https.cdn.then_some(https.server_name.as_str())
    }

    /// A proxied CDN name cannot also be a direct endpoint: every transport, and
    /// publication to an old server, would then reach the CDN instead of the VPS.
    pub fn cdn_host_is_separate(&self) -> bool {
        self.cdn_host().is_none_or(|cdn| {
            std::iter::once(&self.endpoint.host)
                .chain(&self.alternate_endpoint_hosts)
                .all(|host| !host.eq_ignore_ascii_case(cdn))
        })
    }

    /// A CDN proxies only the HTTPS port, which also serves discovery. At the VPS the
    /// retained discovery port still serves devices that know only an older port.
    pub fn discovery_port(&self, through_cdn: bool) -> Option<u16> {
        let tls = self.tls_like.as_ref()?;
        Some(if through_cdn {
            tls.port
        } else {
            self.endpoint_discovery_port.unwrap_or(tls.port)
        })
    }
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
