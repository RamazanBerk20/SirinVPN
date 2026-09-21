use super::*;

fn policy() -> DnsUpstream {
    let mut secure_zone: sirinvpn_protocol::DnsSplitZone =
        "secure.corp.home=10.61.0.3#resolver.fixture"
            .parse()
            .unwrap();
    secure_zone.allow_unsigned_answers = true; // The isolated fixture has no public DNSSEC delegation.
    DnsUpstream::Split {
        default: Box::new(DnsUpstream::DnsOverTls {
            endpoints: vec!["10.61.0.1#resolver.fixture".parse().unwrap()],
        }),
        zones: vec!["corp.home=10.61.0.2".parse().unwrap(), secure_zone],
    }
}

#[test]
fn split_dns_policy_is_preserved_in_init_and_verified_without_global_fallback() {
    let policy = policy();
    let (server, forwarding) = unbound_dns_configuration(&policy, &[]);
    assert!(server.contains("domain-insecure: \"corp.home.\""));
    assert!(!server.contains("domain-insecure: \".\""));
    assert_eq!(forwarding.matches("forward-first: no").count(), 3);
    assert!(!forwarding.contains("forward-first: yes"));
    assert!(server_dns_init_arguments(&policy, &[]).contains("--dns-policy-json"));
    assert!(unbound_dns_verification(&policy, &[]).contains("split DNS configuration differs"));
    assert!(ensure_dns_upstream_compatible(&policy, false).is_ok());
}

#[test]
#[ignore = "requires disposable networking and Unbound; use tests/network/run-split-dns.sh"]
fn kernel_split_dns_uses_the_most_specific_zone_and_never_falls_back_after_failure() {
    assert_eq!(
        std::env::var("SIRINVPN_POLICY_ISOLATED").as_deref(),
        Ok("1")
    );
    assert!(Path::new("/.dockerenv").exists());
    let (server, forwarding) =
        unbound_dns_configuration(&policy(), &["nas.corp.home=10.62.0.5".parse().unwrap()]);
    let mut child = std::process::Command::new("python3")
        .arg("tests/network/split_dns.py")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            serde_json::to_vec(&(server, forwarding))
                .unwrap()
                .as_slice(),
        )
        .unwrap();
    assert!(child.wait().unwrap().success());
}
