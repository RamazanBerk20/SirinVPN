//! Explicit user configuration. No SSID, BSSID, connection time or location log.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WifiAutomationPolicy {
    pub enabled: bool,
    pub server_id: Option<ServerId>,
}
pub(super) fn is_default_policy(policy: &WifiAutomationPolicy) -> bool {
    *policy == WifiAutomationPolicy::default()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedWifiNetwork {
    pub id: String,
    pub label: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WifiNetworkStatus {
    Unavailable,
    OtherNetwork,
    TrustedWifi,
    UntrustedWifi,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WifiPolicySnapshot {
    pub policy: WifiAutomationPolicy,
    pub trusted_networks: Vec<TrustedWifiNetwork>,
    pub current_network: WifiNetworkStatus,
    pub can_trust_current: bool,
    pub current_network_token: Option<String>,
}

impl NetworkPolicyStore {
    /// Resolve only current/trusted names for the local settings UI. Never persist
    /// names or call this from connection discovery, diagnostics, or automation.
    pub fn wifi_display_names(
        &self,
        snapshot: &WifiPolicySnapshot,
    ) -> Result<BTreeMap<String, String>, NetworkPolicyError> {
        if snapshot.current_network_token.is_none() && snapshot.trusted_networks.is_empty() {
            return Ok(BTreeMap::new());
        }
        let Some(document) = self.load_document()? else {
            return Ok(BTreeMap::new());
        };
        let salt = decode_salt(&document.salt_hex)?;
        let wanted = |identifier: &str| wifi_name_key(snapshot, &salt, identifier);
        #[cfg(windows)]
        let names = sirinvpn_platform::windows::network_context::display_names(wanted);
        #[cfg(not(windows))]
        let names = network_manager_names(wanted);
        Ok(names
            .into_iter()
            .filter(|(_, name)| valid_display_name(name))
            .collect())
    }

    pub fn initialize_wifi_settings(&self) -> Result<(), NetworkPolicyError> {
        if self.path.exists() {
            self.load_document()?;
            return Ok(());
        }
        self.mutate(|_| Ok(()))
    }

    pub fn wifi_snapshot(
        &self,
        network: Option<&NetworkContext>,
    ) -> Result<WifiPolicySnapshot, NetworkPolicyError> {
        let document = self
            .load_document()?
            .unwrap_or_else(new_network_policy_document);
        let current_network = match network {
            None => WifiNetworkStatus::Unavailable,
            Some(network) if !network.is_wifi() => WifiNetworkStatus::OtherNetwork,
            Some(network) => {
                let fingerprint = fingerprint_network(&decode_salt(&document.salt_hex)?, network);
                if network.can_trust()
                    && document
                        .trusted_wifi
                        .iter()
                        .any(|trusted| trusted.id == fingerprint)
                {
                    WifiNetworkStatus::TrustedWifi
                } else {
                    WifiNetworkStatus::UntrustedWifi
                }
            }
        };
        Ok(WifiPolicySnapshot {
            policy: document.wifi_automation,
            trusted_networks: document.trusted_wifi,
            current_network,
            can_trust_current: network.is_some_and(NetworkContext::can_trust),
            current_network_token: network.filter(|n| n.is_wifi()).map(|n| {
                fingerprint_network(&decode_salt(&document.salt_hex).expect("validated salt"), n)
            }),
        })
    }

    pub fn set_wifi_automation(
        &self,
        policy: WifiAutomationPolicy,
    ) -> Result<(), NetworkPolicyError> {
        self.mutate(move |document| {
            document.wifi_automation = policy;
            Ok(())
        })
    }

    pub fn trust_wifi(
        &self,
        network: &NetworkContext,
        label: String,
    ) -> Result<(), NetworkPolicyError> {
        if !network.can_trust() {
            return Err(NetworkPolicyError::InvalidData);
        }
        let label = label.trim().to_owned();
        self.mutate(move |document| {
            let id = fingerprint_network(&decode_salt(&document.salt_hex)?, network);
            if let Some(trusted) = document
                .trusted_wifi
                .iter_mut()
                .find(|trusted| trusted.id == id)
            {
                trusted.label = label;
            } else {
                document.trusted_wifi.push(TrustedWifiNetwork { id, label });
            }
            Ok(())
        })
    }

    pub fn forget_trusted_wifi(&self, id: &str) -> Result<(), NetworkPolicyError> {
        self.mutate(|document| {
            document.trusted_wifi.retain(|trusted| trusted.id != id);
            Ok(())
        })
    }
}

fn wifi_name_key(
    snapshot: &WifiPolicySnapshot,
    salt: &[u8; NETWORK_SALT_LENGTH],
    identifier: &str,
) -> Option<String> {
    let context = NetworkContext::from_stable_identifier(identifier)?;
    let id = fingerprint_network(salt, &context);
    (snapshot.current_network_token.as_ref() == Some(&id)
        || snapshot
            .trusted_networks
            .iter()
            .any(|network| network.id == id))
    .then_some(id)
}

fn valid_display_name(name: &str) -> bool {
    !name.trim().is_empty() && name.len() <= 256 && !name.chars().any(char::is_control)
}

#[cfg(not(windows))]
fn network_manager_names(wanted: impl Fn(&str) -> Option<String>) -> BTreeMap<String, String> {
    fn read(args: &[&str], limit: usize) -> Option<String> {
        let output = Command::new("nmcli")
            .args(["--wait", "2", "--terse", "--escape", "no", "--colors", "no"])
            .args(args)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() || output.stdout.len() > limit {
            return None;
        }
        String::from_utf8(output.stdout).ok()
    }
    let mut names = BTreeMap::new();
    let Some(profiles) = read(
        &["--fields", "UUID,TYPE,NAME", "connection", "show"],
        1024 * 1024,
    ) else {
        return names;
    };
    for line in profiles.lines() {
        let Some((uuid, profile_name)) = wifi_profile(line) else {
            continue;
        };
        let Some(id) = wanted(&format!("networkmanager:v1:{}", uuid.to_ascii_lowercase())) else {
            continue;
        };
        // Query only explicitly trusted/current profiles, never scan nearby hotspots.
        let ssid = read(
            &[
                "--get-values",
                "802-11-wireless.ssid",
                "connection",
                "show",
                "uuid",
                uuid,
            ],
            512,
        );
        let name = ssid
            .as_deref()
            .map(|value| value.trim_end_matches('\n'))
            .filter(|name| valid_display_name(name))
            .unwrap_or(profile_name);
        if valid_display_name(name) {
            names.insert(id, name.to_owned());
        }
    }
    names
}

#[cfg(any(not(windows), test))]
fn wifi_profile(line: &str) -> Option<(&str, &str)> {
    let mut parts = line.splitn(3, ':');
    let (uuid, kind, name) = (parts.next()?, parts.next()?, parts.next()?);
    (valid_uuid(uuid) && matches!(kind, "802-11-wireless" | "wifi") && valid_display_name(name))
        .then_some((uuid, name))
}

pub(super) fn validate(document: &NetworkPolicyDocument) -> Result<(), NetworkPolicyError> {
    if (document.wifi_automation.enabled && document.wifi_automation.server_id.is_none())
        || document
            .wifi_automation
            .server_id
            .is_some_and(|id| id.0.is_nil())
        || document.trusted_wifi.len() > 32
        || (document.schema_version < 2
            && (!is_default_policy(&document.wifi_automation) || !document.trusted_wifi.is_empty()))
        || document
            .trusted_wifi
            .iter()
            .enumerate()
            .any(|(i, trusted)| {
                trusted.id.len() != 64
                    || !trusted.id.bytes().all(|c| c.is_ascii_hexdigit())
                    || trusted.label.is_empty()
                    || trusted.label.len() > 80
                    || trusted.label.chars().any(char::is_control)
                    || document.trusted_wifi[..i]
                        .iter()
                        .any(|other| other.id == trusted.id)
            })
    {
        return Err(NetworkPolicyError::InvalidData);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn display_names_match_only_current_or_trusted_networks_without_writing_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network.json");
        let store = NetworkPolicyStore::new(path.clone());
        let mut trusted = NetworkContext::from_stable_identifier("saved-trusted-network").unwrap();
        trusted.wifi = true;
        trusted.trustable = true;
        store
            .trust_wifi(&trusted, "Wi-Fi exception".into())
            .unwrap();
        let mut current = NetworkContext::from_stable_identifier("current-wifi").unwrap();
        current.wifi = true;
        let snapshot = store.wifi_snapshot(Some(&current)).unwrap();
        let before = fs::read(&path).unwrap();
        let document = store.load_document().unwrap().unwrap();
        let salt = decode_salt(&document.salt_hex).unwrap();
        assert_eq!(
            wifi_name_key(&snapshot, &salt, "saved-trusted-network"),
            Some(snapshot.trusted_networks[0].id.clone())
        );
        assert_eq!(
            wifi_name_key(&snapshot, &salt, "current-wifi"),
            snapshot.current_network_token
        );
        assert_eq!(
            wifi_name_key(&snapshot, &salt, "unrelated-saved-network"),
            None
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(valid_display_name("Home: 5 GHz \\ Café"));
        assert!(!valid_display_name("\nspoofed name"));
        assert!(!valid_display_name(" "));
    }

    #[test]
    fn wifi_profile_parser_preserves_names_and_rejects_other_connections() {
        let uuid = "12345678-1234-1234-1234-123456789abc";
        assert_eq!(
            wifi_profile(&format!("{uuid}:802-11-wireless:Home: 5 GHz \\ Café")),
            Some((uuid, "Home: 5 GHz \\ Café"))
        );
        assert!(wifi_profile(&format!("{uuid}:ethernet:Wired")).is_none());
        assert!(wifi_profile("invalid:wifi:Home").is_none());
        assert!(wifi_profile(&format!("{uuid}:wifi:bad\nname")).is_none());
    }
    #[test]
    fn wifi_is_untrusted_until_explicitly_selected_and_does_not_create_location_history() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network.json");
        let store = NetworkPolicyStore::new(path.clone());
        let mut network = NetworkContext::from_stable_identifier("private-network-UUID").unwrap();
        network.wifi = true;
        network.trustable = true;
        assert_eq!(
            store.wifi_snapshot(Some(&network)).unwrap().current_network,
            WifiNetworkStatus::UntrustedWifi
        );
        assert!(
            !path.exists(),
            "discovery alone must not persist visited networks"
        );
        let server = ServerId::new();
        store
            .set_wifi_automation(WifiAutomationPolicy {
                enabled: true,
                server_id: Some(server),
            })
            .unwrap();
        store.trust_wifi(&network, "Home".into()).unwrap();
        let snapshot = store.wifi_snapshot(Some(&network)).unwrap();
        assert_eq!(snapshot.current_network, WifiNetworkStatus::TrustedWifi);
        let bytes = fs::read_to_string(&path).unwrap();
        assert!(!bytes.contains("private-network-UUID"));
        assert!(!bytes.contains("timestamp"));
        assert!(bytes.contains("Home"));
        network.trustable = false;
        assert_eq!(
            store.wifi_snapshot(Some(&network)).unwrap().current_network,
            WifiNetworkStatus::UntrustedWifi
        );
        assert!(store.trust_wifi(&network, "Unknown".into()).is_err());
        store.forget_server(server).unwrap();
        assert!(!store.wifi_snapshot(None).unwrap().policy.enabled);
        store
            .forget_trusted_wifi(&snapshot.trusted_networks[0].id)
            .unwrap();
        assert!(
            store
                .wifi_snapshot(None)
                .unwrap()
                .trusted_networks
                .is_empty()
        );
    }
}
