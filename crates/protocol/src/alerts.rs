//! Opt-in VPS alerts. The VPS sends fixed English text to one Owner-chosen HTTPS address and
//! can ping a second one as a heartbeat. No names, addresses, counts or traffic data are sent.
use crate::normalize_dns_blocklist_name;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const MAX_ALERT_URL_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertFormat {
    /// Plain-text body with a `Title` header, as an ntfy topic expects.
    #[default]
    Ntfy,
    /// A small JSON object; see docs/vps-alerts.md.
    Webhook,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertPolicy {
    /// Receives problem, recovery and test notices. Alerts are off without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_url: Option<String>,
    #[serde(default)]
    pub format: AlertFormat,
    /// Requested every five minutes so an outside monitor notices when the VPS goes silent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_url: Option<String>,
    /// Lets either address be, or resolve to, a private, loopback or VPN address.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_private_addresses: bool,
}

impl AlertPolicy {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self
            .alert_url
            .iter()
            .chain(&self.heartbeat_url)
            .any(|url| !valid_alert_url(url, self.allow_private_addresses))
        {
            return Err(
                "alert addresses must use HTTPS without credentials or a fragment, and reach a public host unless private addresses are allowed",
            );
        }
        Ok(())
    }
}

/// An absolute HTTPS address without credentials or fragment whose host is a DNS name or an
/// IP literal. IP literals must be public unless `allow_private`; names are checked again
/// after resolution, just before each request.
pub fn valid_alert_url(value: &str, allow_private: bool) -> bool {
    let Some(rest) = value
        .strip_prefix("https:")
        .and_then(|rest| rest.strip_prefix("//"))
    else {
        return false;
    };
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    let (host, port, bracketed) = match authority.strip_prefix('[') {
        Some(inner) => match inner.split_once(']') {
            Some((host, port)) => (host, port, true),
            None => return false,
        },
        None => match authority.rsplit_once(':') {
            Some((host, _)) => (host, &authority[host.len()..], false),
            None => (authority, "", false),
        },
    };
    let port_valid = port.is_empty()
        || port.strip_prefix(':').is_some_and(|port| {
            port.bytes().all(|byte| byte.is_ascii_digit())
                && port.parse::<u16>().is_ok_and(|port| port > 0)
        });
    let host_valid = match host.parse::<IpAddr>() {
        Ok(address) => {
            bracketed == address.is_ipv6() && (allow_private || public_ip_address(address))
        }
        Err(_) => {
            !bracketed
                && normalize_dns_blocklist_name(host).as_deref() == Some(host)
                && (allow_private || !host.ends_with(".localhost"))
        }
    };
    value.len() <= MAX_ALERT_URL_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
        && !value.contains(['#', '\\', '"', '\''])
        && !authority.contains('@')
        && port_valid
        && host_valid
}

/// Globally routed unicast only: no private, loopback, link-local, shared, documentation,
/// benchmark, multicast or reserved address, and only 2000::/3 for IPv6.
pub fn public_ip_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, _] = address.octets();
            a != 0
                && a != 10
                && a != 127
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 169 && b == 254)
                && !(a == 172 && (16..=31).contains(&b))
                && !(a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2))))
                && !(a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                && !(a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            segments[0] & 0xe000 == 0x2000 && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertFailure {
    /// The name did not resolve, or resolved to a private address that is not allowed.
    Address,
    /// No HTTPS response: connection, TLS or timeout.
    Connection,
    /// The receiver answered with a non-success HTTP status.
    Rejected,
}

/// The latest outcomes of the VPS alert task. It records no problem history.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertStatus {
    pub checked_at_unix: Option<u64>,
    pub alert_sent_at_unix: Option<u64>,
    pub alert_failure: Option<AlertFailure>,
    pub heartbeat_sent_at_unix: Option<u64>,
    pub heartbeat_failure: Option<AlertFailure>,
    /// Fingerprint of the policy these outcomes belong to.
    pub policy_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AlertSettings {
    pub policy: AlertPolicy,
    pub status: AlertStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AlertTestResult {
    pub failure: Option<AlertFailure>,
    pub http_status: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_addresses_are_https_without_credentials_and_public_unless_allowed() {
        for valid in [
            "https://ntfy.example/sirinvpn-alerts",
            "https://ntfy.example:8443/topic?auth=abc",
            "https://hooks.example/a/b?token=x&y=1",
            "https://9.9.9.9/topic",
            "https://[2606:4700::1111]:443/topic",
        ] {
            assert!(valid_alert_url(valid, false), "{valid}");
        }
        for private in [
            "https://10.77.0.5/topic",
            "https://127.0.0.1:8080/topic",
            "https://192.168.1.10/topic",
            "https://100.64.0.1/topic",
            "https://169.254.169.254/latest",
            "https://[::1]/topic",
            "https://[fd00::1]/topic",
            "https://[::ffff:10.0.0.1]/topic",
            "https://ntfy.localhost/topic",
        ] {
            assert!(!valid_alert_url(private, false), "{private}");
            assert!(valid_alert_url(private, true), "{private}");
        }
        for invalid in [
            "http://ntfy.example/topic",
            "https://user:pass@ntfy.example/topic",
            "https://ntfy.example/topic#x",
            "https://ntfy.example/a b",
            "https://localhost/topic",
            "https://ntfy/topic",
            "https://ntfy.example:/topic",
            "https://ntfy.example:0/topic",
            "https://ntfy.example:65536/topic",
            "https://ntfy.example:+443/topic",
            "https://[ntfy.example]/topic",
            "https://2606:4700::1111/topic",
            "https://[192.0.2.1]/topic",
            "https:///topic",
            "ntfy.example/topic",
        ] {
            assert!(!valid_alert_url(invalid, true), "{invalid}");
        }
        assert!(!valid_alert_url(
            &format!("https://ntfy.example/{}", "a".repeat(MAX_ALERT_URL_BYTES)),
            false
        ));
    }

    #[test]
    fn a_policy_checks_both_addresses_with_its_own_private_choice() {
        assert!(AlertPolicy::default().validate().is_ok());
        let mut policy = AlertPolicy {
            alert_url: Some("https://ntfy.example/topic".into()),
            heartbeat_url: Some("https://10.77.0.5/ping".into()),
            ..Default::default()
        };
        assert!(policy.validate().is_err());
        policy.allow_private_addresses = true;
        assert!(policy.validate().is_ok());
        policy.alert_url = Some("http://ntfy.example/topic".into());
        assert!(policy.validate().is_err());
    }
}
