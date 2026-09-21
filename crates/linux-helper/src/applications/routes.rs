use super::*;
use serde_json::Value;

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    pub(super) fn application_rules_verified(&self, request: &TunnelConnectRequest) -> bool {
        let dns = format!("{}/32", request.dns_address);
        self.application_rule_matches("-4", DNS_RULE_PRIORITY, None, Some(&dns), Some(51820))
            && self.application_rule_matches(
                "-4",
                DNS_BLOCK_PRIORITY,
                Some(HOST_LINK),
                Some(&dns),
                None,
            )
            && ["-4", "-6"].into_iter().all(|family| {
                self.application_fallback_rule_exists(family)
                    && (family == "-6" && request.client_ipv6_address.is_none()
                        || self.application_rule_matches(
                            family,
                            RULE_TUNNEL_PRIORITY,
                            Some(HOST_LINK),
                            None,
                            Some(51820),
                        ))
            })
            && (!request.routing.allow_lan
                || IPV4_LAN_ROUTES.iter().enumerate().all(|(index, route)| {
                    self.application_rule_matches(
                        "-4",
                        &(LAN_RULE_PRIORITY_START + 1 + index as u16).to_string(),
                        Some(HOST_LINK),
                        Some(route),
                        Some(254),
                    )
                }))
    }

    pub(super) fn application_rule_matches(
        &self,
        family: &str,
        priority: &str,
        input: Option<&str>,
        destination: Option<&str>,
        table: Option<u64>,
    ) -> bool {
        self.runner
            .output("ip", &[family, "-j", "rule", "show", "priority", priority])
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Vec<Value>>(&bytes).ok())
            .is_some_and(|rules| {
                rules.len() == 1
                    && rule_matches(
                        &rules[0],
                        priority.parse().unwrap_or(0),
                        input,
                        destination,
                        table,
                    )
            })
    }

    pub(super) fn application_forwarding_verified(&self, request: &TunnelConnectRequest) -> bool {
        let enabled = |family: &str, link: &str, flag: &str| {
            fs::read_to_string(format!("/proc/sys/net/{family}/conf/{link}/{flag}"))
                .is_ok_and(|value| value.trim() == "1")
        };
        [INTERFACE_NAME, HOST_LINK]
            .into_iter()
            .filter(|link| *link != HOST_LINK || self.application_path().exists())
            .all(|link| {
                enabled("ipv4", link, "forwarding")
                    && (request.client_ipv6_address.is_none()
                        || !ipv6_forwarding_available()
                        || enabled("ipv6", "all", "forwarding")
                        || enabled("ipv6", link, "force_forwarding"))
            })
    }
}

fn network(value: &str) -> Option<IpNet> {
    value
        .parse()
        .ok()
        .or_else(|| value.parse::<IpAddr>().ok().map(IpNet::from))
}

fn all_addresses(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        value == "all" || network(value).is_some_and(|net| net.prefix_len() == 0)
    })
}

fn rule_matches(
    rule: &Value,
    priority: u64,
    input: Option<&str>,
    destination: Option<&str>,
    table: Option<u64>,
) -> bool {
    let Some(object) = rule.as_object() else {
        return false;
    };
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "priority"
                | "src"
                | "srclen"
                | "dst"
                | "dstlen"
                | "iif"
                | "iif_detached"
                | "table"
                | "action"
                | "protocol"
                | "flags"
        )
    }) || rule["priority"].as_u64() != Some(priority)
        || !all_addresses(rule.get("src").and_then(Value::as_str))
        || rule
            .get("srclen")
            .is_some_and(|length| length.as_u64() != Some(0))
        || rule.get("iif").and_then(Value::as_str) != input
        || rule
            .get("iif_detached")
            .is_some_and(|value| !value.is_null())
        || rule
            .get("flags")
            .is_some_and(|flags| !flags.as_array().is_some_and(Vec::is_empty))
    {
        return false;
    }
    let actual_destination = rule.get("dst").and_then(Value::as_str);
    let destination_matches = match destination {
        Some(expected) => actual_destination
            .and_then(|address| match rule.get("dstlen") {
                Some(length) => {
                    let length = u8::try_from(length.as_u64()?).ok()?;
                    IpNet::new(address.parse().ok()?, length).ok()
                }
                None => network(address),
            })
            .is_some_and(|actual| Some(actual) == network(expected)),
        None => {
            all_addresses(actual_destination)
                && rule
                    .get("dstlen")
                    .is_none_or(|length| length.as_u64() == Some(0))
        }
    };
    destination_matches
        && match table {
            Some(expected) => {
                (rule["table"].as_u64() == Some(expected)
                    || rule["table"].as_str().is_some_and(|name| {
                        name.parse() == Ok(expected) || expected == 254 && name == "main"
                    }))
                    && rule.get("action").is_none_or(|action| action == "to_tbl")
            }
            None => rule["action"] == "prohibit" && !object.contains_key("table"),
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn inverted_broadened_or_extra_selectors_do_not_confirm_protection() {
        let original =
            json!({"priority":10002,"src":"all","iif":HOST_LINK,"action":"prohibit","flags":[]});
        assert!(rule_matches(&original, 10002, Some(HOST_LINK), None, None));
        for (key, value) in [
            ("not", json!(true)),
            ("src", json!("192.0.2.0/24")),
            ("flags", json!(["not"])),
        ] {
            let mut altered = original.clone();
            altered[key] = value;
            assert!(!rule_matches(&altered, 10002, Some(HOST_LINK), None, None));
        }
        let mut broadened = original.clone();
        broadened.as_object_mut().unwrap().remove("iif");
        assert!(!rule_matches(
            &broadened,
            10002,
            Some(HOST_LINK),
            None,
            None
        ));
        let lookup =
            json!({"priority":9990,"src":"all","dst":"10.77.0.1","table":51820,"flags":[]});
        assert!(rule_matches(
            &lookup,
            9990,
            None,
            Some("10.77.0.1/32"),
            Some(51820)
        ));
        assert!(!rule_matches(
            &lookup,
            9990,
            None,
            Some("10.77.0.2/32"),
            Some(51820)
        ));
        let lan = json!({"priority":9992,"src":"all","dst":"10.0.0.0","dstlen":8,"iif":HOST_LINK,"table":"main"});
        assert!(rule_matches(
            &lan,
            9992,
            Some(HOST_LINK),
            Some("10.0.0.0/8"),
            Some(254)
        ));
    }
}
