//! Explicit per-zone DNS forwarding from the private VPS resolver.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsSplitZone {
    pub suffix: String,
    pub upstream: SplitDnsUpstream,
    /// An explicit exception for unsigned private namespaces, never for the root zone.
    #[serde(default)]
    pub allow_unsigned_answers: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum SplitDnsUpstream {
    Private { addresses: Vec<IpAddr> },
    DnsOverTls { endpoints: Vec<DnsOverTlsEndpoint> },
}

impl DnsSplitZone {
    pub fn validate(&self) -> Result<(), ValidationError> {
        let name = &self.suffix;
        if !dns::valid_dns_authentication_name(name)
            || name.split('.').count() < 2
            || name.parse::<IpAddr>().is_ok()
            || name.ends_with(".localhost")
            || name.ends_with(".local")
        {
            return Err(ValidationError::InvalidSplitDns);
        }
        match &self.upstream {
            SplitDnsUpstream::Private { addresses } => {
                if addresses.is_empty() || addresses.len() > 4 {
                    return Err(ValidationError::InvalidSplitDns);
                }
                for (index, address) in addresses.iter().enumerate() {
                    let private = match address {
                        IpAddr::V4(ip) => {
                            ip.is_private()
                                && *ip != Ipv4Addr::new(10, 77, 0, 1)
                                && !(ip.octets()[..3] == [10, 77, 0] && ip.octets()[3] >= 224)
                        }
                        IpAddr::V6(ip) => ip.is_unique_local(),
                    };
                    if !private || addresses[..index].contains(address) {
                        return Err(ValidationError::InvalidSplitDns);
                    }
                }
            }
            SplitDnsUpstream::DnsOverTls { endpoints } => {
                validate_dns_upstream(&DnsUpstream::DnsOverTls {
                    endpoints: endpoints.clone(),
                })?
            }
        }
        Ok(())
    }
    pub fn addresses(&self) -> Vec<IpAddr> {
        match &self.upstream {
            SplitDnsUpstream::Private { addresses } => addresses.clone(),
            SplitDnsUpstream::DnsOverTls { endpoints } => {
                endpoints.iter().map(|endpoint| endpoint.address).collect()
            }
        }
    }
}

impl std::str::FromStr for DnsSplitZone {
    type Err = ValidationError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (suffix, resolvers) = value
            .trim()
            .split_once('=')
            .ok_or(ValidationError::InvalidSplitDns)?;
        let suffix = suffix.trim().trim_end_matches('.').to_ascii_lowercase();
        let secure = resolvers.contains('#');
        let upstream = if secure {
            SplitDnsUpstream::DnsOverTls {
                endpoints: resolvers
                    .split(',')
                    .map(str::parse)
                    .collect::<Result<_, _>>()?,
            }
        } else {
            SplitDnsUpstream::Private {
                addresses: resolvers
                    .split(',')
                    .map(|ip| {
                        ip.trim()
                            .parse()
                            .map_err(|_| ValidationError::InvalidSplitDns)
                    })
                    .collect::<Result<_, _>>()?,
            }
        };
        let zone = Self {
            suffix,
            upstream,
            allow_unsigned_answers: !secure,
        };
        zone.validate()?;
        Ok(zone)
    }
}

pub fn validate_split_dns(
    default: &DnsUpstream,
    zones: &[DnsSplitZone],
) -> Result<(), ValidationError> {
    if matches!(default, DnsUpstream::Split { .. }) || zones.is_empty() || zones.len() > 16 {
        return Err(ValidationError::InvalidSplitDns);
    }
    validate_dns_upstream(default)?;
    for (index, zone) in zones.iter().enumerate() {
        zone.validate()?;
        if zones[..index]
            .iter()
            .any(|previous| previous.suffix == zone.suffix)
        {
            return Err(ValidationError::InvalidSplitDns);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn split_zones_are_explicit_bounded_and_cannot_replace_global_policy() {
        let private: DnsSplitZone = "office.home=10.20.0.53,10.20.0.54".parse().unwrap();
        assert!(private.allow_unsigned_answers);
        let secure: DnsSplitZone = "corp.example=192.0.2.53#dns.example.com".parse().unwrap();
        assert!(!secure.allow_unsigned_answers);
        let policy = DnsUpstream::Split {
            default: Box::new(DnsUpstream::Recursive),
            zones: vec![private.clone(), secure],
        };
        assert!(validate_dns_upstream(&policy).is_ok());
        assert_eq!(server_dns_configuration_schema_version(&policy, &[]), 6);
        assert!(validate_server_dns_configuration(5, &policy, &[]).is_err());
        assert!(validate_split_dns(&policy, std::slice::from_ref(&private)).is_err());
        assert!(validate_split_dns(&DnsUpstream::Recursive, &[private.clone(), private]).is_err());
        for invalid in [
            ".=10.20.0.53",
            "com=10.20.0.53",
            "office.home=1.1.1.1",
            "office.home=127.0.0.1",
            "office.home=10.77.0.1",
            "office.home=10.77.0.254",
            "home.local=10.20.0.53",
            "home.example=10.0.0.1#tls.example,10.0.0.2",
            "bad\nname.home=10.0.0.1",
        ] {
            assert!(invalid.parse::<DnsSplitZone>().is_err(), "{invalid}");
        }
    }
}
