//! Opt-in DNS ad and tracker blocking on the VPS resolver. Only the current policy and the
//! last refresh outcome exist; no query, device or per-domain activity is recorded.
use serde::{Deserialize, Serialize};

pub const MAX_DNS_BLOCKLIST_SOURCES: usize = 8;
pub const MAX_DNS_BLOCKLIST_ALLOWLIST: usize = 512;
pub const MAX_DNS_BLOCKLIST_URL_BYTES: usize = 2048;
/// Unique names accepted across all lists; a larger result keeps the previous list.
pub const MAX_DNS_BLOCKLIST_DOMAINS: usize = 300_000;
pub const MAX_DNS_BLOCKLIST_DOWNLOAD_BYTES: u64 = 16 * 1024 * 1024;

/// Well-known lists offered by the apps. Any other HTTPS list may be added.
pub const BUILT_IN_DNS_BLOCKLISTS: [(&str, &str); 4] = [
    (
        "HaGeZi Multi Light",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
    ),
    (
        "HaGeZi Multi Normal",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt",
    ),
    ("OISD Small", "https://small.oisd.nl/domainswild2"),
    (
        "StevenBlack Unified Hosts",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
];

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsBlocklistPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowlist: Vec<String>,
}

impl DnsBlocklistPolicy {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.enabled && self.sources.is_empty() {
            return Err("choose at least one blocklist before enabling DNS blocking");
        }
        if self.sources.len() > MAX_DNS_BLOCKLIST_SOURCES
            || self.sources.iter().any(|url| !valid_dns_blocklist_url(url))
            || has_duplicates(&self.sources)
        {
            return Err("blocklists must be up to 8 unique HTTPS addresses");
        }
        if self.allowlist.len() > MAX_DNS_BLOCKLIST_ALLOWLIST
            || self
                .allowlist
                .iter()
                .any(|name| normalize_dns_blocklist_name(name).as_deref() != Some(name))
            || has_duplicates(&self.allowlist)
        {
            return Err("allowed domains must be up to 512 unique lowercase DNS names");
        }
        Ok(())
    }
}

fn has_duplicates(values: &[String]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

/// An absolute HTTPS address without credentials or fragment. Downloads never follow redirects.
pub fn valid_dns_blocklist_url(value: &str) -> bool {
    let Some(rest) = value
        .strip_prefix("https:")
        .and_then(|rest| rest.strip_prefix("//"))
    else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or_default();
    let host = authority
        .rsplit_once(':')
        .filter(|(_, port)| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or(authority, |(host, _)| host);
    value.len() <= MAX_DNS_BLOCKLIST_URL_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
        && !value.contains(['#', '\\', '"', '\''])
        && !authority.contains('@')
        && normalize_dns_blocklist_name(host).as_deref() == Some(host)
}

/// Canonical lowercase name without the trailing dot, or `None` if it is not a multi-label DNS
/// name. Underscores are allowed because blocklists contain service names.
pub fn normalize_dns_blocklist_name(value: &str) -> Option<String> {
    let name = value
        .strip_suffix('.')
        .unwrap_or(value)
        .to_ascii_lowercase();
    let labels = name.split('.').collect::<Vec<_>>();
    (name.len() <= 253
        && labels.len() >= 2
        && !labels.last()?.bytes().all(|byte| byte.is_ascii_digit())
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        }))
    .then_some(name)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsBlocklistFailure {
    Download,
    Format,
    TooManyDomains,
    Resolver,
}

/// The applied list and the outcome of the latest refresh, written only by the VPS root task.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsBlocklistStatus {
    pub active: bool,
    pub domain_count: u32,
    pub updated_at_unix: Option<u64>,
    /// Policy and DNS-configuration fingerprint the active list was built from.
    pub policy_sha256: Option<String>,
    pub failure: Option<DnsBlocklistFailure>,
    pub failed_at_unix: Option<u64>,
    pub failed_policy_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DnsBlocklistPreset {
    pub name: String,
    pub url: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DnsBlocklistSettings {
    pub policy: DnsBlocklistPolicy,
    pub status: DnsBlocklistStatus,
    /// The saved policy has not been applied by the VPS yet.
    pub pending: bool,
    pub presets: Vec<DnsBlocklistPreset>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_canonical_multi_label_dns_names() {
        assert_eq!(
            normalize_dns_blocklist_name("Ads.Example.COM.").as_deref(),
            Some("ads.example.com")
        );
        assert_eq!(
            normalize_dns_blocklist_name("_dmarc.example.com").as_deref(),
            Some("_dmarc.example.com")
        );
        for invalid in [
            "localhost",
            "0.0.0.0",
            "10.0.0.1",
            "-bad.example",
            "bad-.example",
            "a..example",
            "spa ce.example",
            "quote\".example",
            "",
            ".",
        ] {
            assert_eq!(normalize_dns_blocklist_name(invalid), None, "{invalid}");
        }
        assert!(normalize_dns_blocklist_name(&format!("{}.example", "a".repeat(64))).is_none());
        assert!(normalize_dns_blocklist_name(&format!("{}.example", "a.".repeat(124))).is_none());
    }

    #[test]
    fn list_addresses_are_https_without_credentials_or_fragments() {
        for (_, url) in BUILT_IN_DNS_BLOCKLISTS {
            assert!(valid_dns_blocklist_url(url), "{url}");
        }
        assert!(valid_dns_blocklist_url(
            "https://lists.example:8443/a.txt?v=1"
        ));
        for invalid in [
            "http://lists.example/a.txt",
            "https://user@lists.example/a.txt",
            "https://lists.example/a.txt#x",
            "https://lists.example/a b.txt",
            "https://localhost/a.txt",
            "https://192.0.2.1/a.txt",
            "https://lists.example:/a.txt",
            "https:///a.txt",
        ] {
            assert!(!valid_dns_blocklist_url(invalid), "{invalid}");
        }
        assert!(!valid_dns_blocklist_url(&format!(
            "https://lists.example/{}",
            "a".repeat(MAX_DNS_BLOCKLIST_URL_BYTES)
        )));
    }

    #[test]
    fn policy_bounds_sources_and_allowlist() {
        let source = BUILT_IN_DNS_BLOCKLISTS[0].1.to_owned();
        assert!(DnsBlocklistPolicy::default().validate().is_ok());
        let enabled_without_lists = DnsBlocklistPolicy {
            enabled: true,
            ..Default::default()
        };
        assert!(enabled_without_lists.validate().is_err());
        let mut policy = DnsBlocklistPolicy {
            enabled: true,
            sources: vec![source.clone()],
            allowlist: vec!["cdn.example.com".into()],
        };
        assert!(policy.validate().is_ok());
        policy.sources.push(source);
        assert!(policy.validate().is_err());
        policy.sources = (0..=MAX_DNS_BLOCKLIST_SOURCES)
            .map(|index| format!("https://lists.example/{index}.txt"))
            .collect();
        assert!(policy.validate().is_err());
        policy.sources.truncate(1);
        policy.allowlist = vec!["CDN.example.com".into()];
        assert!(policy.validate().is_err());
        policy.allowlist = (0..=MAX_DNS_BLOCKLIST_ALLOWLIST)
            .map(|index| format!("n{index}.example"))
            .collect();
        assert!(policy.validate().is_err());
    }
}
