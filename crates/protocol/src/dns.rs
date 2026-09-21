//! Dns.

use super::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DnsOverTlsEndpoint {
    pub address: IpAddr,
    pub authentication_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DnsOverHttpsEndpoint {
    pub address: IpAddr,
    pub authentication_name: String,
    pub path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateDnsRecord {
    pub name: String,
    pub address: IpAddr,
}

impl fmt::Display for DnsOverTlsEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}#{}", self.address, self.authentication_name)
    }
}

impl std::str::FromStr for DnsOverTlsEndpoint {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, authentication_name) = value
            .trim()
            .rsplit_once('#')
            .ok_or(ValidationError::InvalidDnsOverTlsEndpoint)?;
        let endpoint = Self {
            address: address
                .trim()
                .parse()
                .map_err(|_| ValidationError::InvalidDnsOverTlsEndpoint)?,
            authentication_name: authentication_name.trim().to_ascii_lowercase(),
        };
        validate_dns_over_tls_endpoint(&endpoint)?;
        Ok(endpoint)
    }
}

impl fmt::Display for DnsOverHttpsEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}#{}{}",
            self.address, self.authentication_name, self.path
        )
    }
}

impl std::str::FromStr for DnsOverHttpsEndpoint {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, authority_and_path) = value
            .trim()
            .rsplit_once('#')
            .ok_or(ValidationError::InvalidDnsOverHttpsEndpoint)?;
        let path_offset = authority_and_path
            .find('/')
            .ok_or(ValidationError::InvalidDnsOverHttpsEndpoint)?;
        let endpoint = Self {
            address: address
                .trim()
                .parse()
                .map_err(|_| ValidationError::InvalidDnsOverHttpsEndpoint)?,
            authentication_name: authority_and_path[..path_offset]
                .trim()
                .to_ascii_lowercase(),
            path: authority_and_path[path_offset..].trim().to_owned(),
        };
        validate_dns_over_https_endpoint(&endpoint)?;
        Ok(endpoint)
    }
}

impl fmt::Display for PrivateDnsRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}={}", self.name, self.address)
    }
}

impl std::str::FromStr for PrivateDnsRecord {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, address) = value
            .trim()
            .split_once('=')
            .ok_or(ValidationError::InvalidPrivateDnsRecord)?;
        let record = Self {
            name: name
                .trim()
                .strip_suffix('.')
                .unwrap_or(name.trim())
                .to_ascii_lowercase(),
            address: address
                .trim()
                .parse()
                .map_err(|_| ValidationError::InvalidPrivateDnsRecord)?,
        };
        validate_private_dns_record(&record)?;
        Ok(record)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum DnsUpstream {
    #[default]
    Recursive,
    DnsOverTls {
        endpoints: Vec<DnsOverTlsEndpoint>,
    },
    DnsOverHttps {
        endpoints: Vec<DnsOverHttpsEndpoint>,
    },
    Split {
        default: Box<DnsUpstream>,
        zones: Vec<DnsSplitZone>,
    },
}

impl DnsUpstream {
    pub fn is_recursive(&self) -> bool {
        matches!(self, Self::Recursive)
    }

    pub fn default_upstream(&self) -> &Self {
        match self {
            Self::Split { default, .. } => default,
            _ => self,
        }
    }

    pub fn doh_endpoints(&self) -> Option<&[DnsOverHttpsEndpoint]> {
        match self.default_upstream() {
            Self::DnsOverHttps { endpoints } => Some(endpoints),
            _ => None,
        }
    }

    pub fn split_zones(&self) -> &[DnsSplitZone] {
        match self {
            Self::Split { zones, .. } => zones,
            _ => &[],
        }
    }

    pub fn server_configuration_schema_version(&self) -> u16 {
        match self {
            Self::Recursive => 1,
            Self::DnsOverTls { .. } => 2,
            Self::DnsOverHttps { .. } => 4,
            Self::Split { .. } => 6,
        }
    }
}

pub fn server_dns_configuration_schema_version(
    upstream: &DnsUpstream,
    private_records: &[PrivateDnsRecord],
) -> u16 {
    match (upstream, private_records.is_empty()) {
        (DnsUpstream::Split { .. }, _) => 6,
        (_, true) => upstream.server_configuration_schema_version(),
        (DnsUpstream::DnsOverHttps { .. }, false) => 5,
        (_, false) => 3,
    }
}

pub(super) fn is_recursive_dns_upstream(value: &DnsUpstream) -> bool {
    value.is_recursive()
}

pub fn validate_server_name(name: &str) -> Result<(), ValidationError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 64 || trimmed.chars().any(char::is_control) {
        return Err(ValidationError::InvalidServerName);
    }
    Ok(())
}

pub fn validate_host(host: &str) -> Result<(), ValidationError> {
    let trimmed = host.trim();
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return if ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local())
        {
            Err(ValidationError::InvalidHost)
        } else {
            Ok(())
        };
    }
    let valid_dns_name = !trimmed.is_empty()
        && trimmed.len() <= 253
        && trimmed.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        });
    if !valid_dns_name {
        return Err(ValidationError::InvalidHost);
    }
    Ok(())
}

pub fn validate_dns_over_tls_endpoint(
    endpoint: &DnsOverTlsEndpoint,
) -> Result<(), ValidationError> {
    if !usable_dns_endpoint_address(endpoint.address) {
        return Err(ValidationError::InvalidDnsUpstreamAddress);
    }
    if !valid_dns_authentication_name(&endpoint.authentication_name) {
        return Err(ValidationError::InvalidDnsAuthenticationName);
    }
    Ok(())
}

pub fn validate_dns_over_https_endpoint(
    endpoint: &DnsOverHttpsEndpoint,
) -> Result<(), ValidationError> {
    if !usable_dns_endpoint_address(endpoint.address) {
        return Err(ValidationError::InvalidDnsUpstreamAddress);
    }
    if !valid_dns_authentication_name(&endpoint.authentication_name) {
        return Err(ValidationError::InvalidDnsAuthenticationName);
    }
    if !valid_dns_over_https_path(&endpoint.path) {
        return Err(ValidationError::InvalidDnsOverHttpsPath);
    }
    Ok(())
}

pub(super) fn usable_dns_endpoint_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.octets()[0] != 0
                && !address.is_loopback()
                && !address.is_link_local()
                && address.octets()[0] < 224
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unicast_link_local()
        }
    }
}

pub(super) fn valid_dns_authentication_name(name: &str) -> bool {
    if name.is_empty()
        || name.len() > 253
        || name.ends_with('.')
        || name != name.to_ascii_lowercase()
        || !name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
    {
        return false;
    }
    true
}

pub(super) fn valid_dns_over_https_path(path: &str) -> bool {
    if path.is_empty() || path.len() > 255 || !path.starts_with('/') || !path.is_ascii() {
        return false;
    }
    let bytes = path.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        let byte = bytes[offset];
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~') {
            offset += 1;
        } else if byte == b'%'
            && offset + 2 < bytes.len()
            && bytes[offset + 1].is_ascii_hexdigit()
            && bytes[offset + 2].is_ascii_hexdigit()
        {
            offset += 3;
        } else {
            return false;
        }
    }
    true
}

pub fn validate_dns_upstream(upstream: &DnsUpstream) -> Result<(), ValidationError> {
    match upstream {
        DnsUpstream::Split { default, zones } => validate_split_dns(default, zones),
        DnsUpstream::Recursive => Ok(()),
        DnsUpstream::DnsOverTls { endpoints } => {
            if endpoints.is_empty() || endpoints.len() > MAX_DNS_OVER_TLS_ENDPOINTS {
                return Err(ValidationError::InvalidDnsUpstreamEndpoints);
            }
            for (index, endpoint) in endpoints.iter().enumerate() {
                validate_dns_over_tls_endpoint(endpoint)?;
                if endpoints[..index].iter().any(|existing| {
                    existing.address == endpoint.address
                        && existing.authentication_name == endpoint.authentication_name
                }) {
                    return Err(ValidationError::InvalidDnsUpstreamEndpoints);
                }
            }
            Ok(())
        }
        DnsUpstream::DnsOverHttps { endpoints } => {
            if endpoints.is_empty() || endpoints.len() > MAX_DNS_OVER_HTTPS_ENDPOINTS {
                return Err(ValidationError::InvalidDnsOverHttpsEndpoints);
            }
            for (index, endpoint) in endpoints.iter().enumerate() {
                validate_dns_over_https_endpoint(endpoint)?;
                if endpoints[..index]
                    .iter()
                    .any(|existing| existing == endpoint)
                {
                    return Err(ValidationError::InvalidDnsOverHttpsEndpoints);
                }
            }
            Ok(())
        }
    }
}

pub fn validate_private_dns_record(record: &PrivateDnsRecord) -> Result<(), ValidationError> {
    let name = record.name.as_str();
    if name.is_empty()
        || name.len() > 253
        || name.ends_with('.')
        || name != name.to_ascii_lowercase()
        || name.parse::<IpAddr>().is_ok()
        || name.split('.').count() < 2
        || !name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
        || name == "localhost"
        || name.ends_with(".localhost")
    {
        return Err(ValidationError::InvalidPrivateDnsName);
    }

    let usable_address = match record.address {
        IpAddr::V4(address) => {
            address.octets()[0] != 0
                && !address.is_loopback()
                && !address.is_link_local()
                && address.octets()[0] < 224
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unicast_link_local()
        }
    };
    if !usable_address {
        return Err(ValidationError::InvalidPrivateDnsAddress);
    }
    Ok(())
}

pub fn validate_private_dns_records(records: &[PrivateDnsRecord]) -> Result<(), ValidationError> {
    if records.len() > MAX_PRIVATE_DNS_RECORDS {
        return Err(ValidationError::InvalidPrivateDnsRecords);
    }
    for (index, record) in records.iter().enumerate() {
        validate_private_dns_record(record)?;
        if records[..index].iter().any(|existing| existing == record) {
            return Err(ValidationError::InvalidPrivateDnsRecords);
        }
    }
    Ok(())
}
