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
    assert!(ensure_dns_upstream_compatible(&policy, &stack(true, false)).is_ok());
}

#[test]
fn private_record_at_a_split_suffix_keeps_the_rest_of_the_zone_forwarded() {
    let records: Vec<PrivateDnsRecord> = vec![
        "corp.home=10.62.0.4".parse().unwrap(),
        "nas.corp.home=10.62.0.5".parse().unwrap(),
    ];
    let (server, forwarding) = unbound_dns_configuration(&policy(), &records);
    assert!(server.contains("local-zone: \"corp.home.\" transparent"));
    assert!(!server.contains("local-zone: \"corp.home.\" static"));
    assert_eq!(server.matches("local-zone: \"corp.home.\"").count(), 1);
    assert!(server.contains("local-data: \"corp.home. 60 IN A 10.62.0.4\""));
    assert!(server.contains("local-zone: \"nas.corp.home.\" static"));
    assert!(server.contains("local-zone: \"secure.corp.home.\" transparent"));
    assert!(forwarding.contains("name: \"corp.home.\""));
}

#[test]
fn split_dns_verification_is_posix_shell_and_rejects_drift() {
    let policy = policy();
    let records: Vec<PrivateDnsRecord> = vec!["nas.corp.home=10.62.0.5".parse().unwrap()];
    let (server, forwarding) = unbound_dns_configuration(&policy, &records);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sirinvpn.conf");
    let verification = unbound_dns_verification(&policy, &records).replace(
        "/etc/unbound/unbound.conf.d/sirinvpn.conf",
        path.to_str().unwrap(),
    );
    assert!(!verification.contains("python3"));
    let installed = format!(
        "server:\n  interface: 127.0.0.1\n{server}\n  verbosity: 0\n  unwanted-reply-threshold: 100000\n{forwarding}\n"
    );
    let verify = |configuration: &str| {
        fs::write(&path, configuration).unwrap();
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("set -eu\n{verification}"))
            .output()
            .unwrap()
    };
    let accepted = verify(&installed);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    for drift in [
        installed.replacen("forward-first: no", "forward-first: yes", 1),
        installed.replace("10.61.0.2@53", "10.61.0.9@53"),
        installed.replace(" transparent", " static"),
        format!("{installed}\nforward-zone:\n  name: \"other.home.\"\n"),
    ] {
        assert!(!verify(&drift).status.success(), "{drift}");
    }
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

#[test]
fn recursive_dns_verification_fails_when_a_forbidden_line_is_present() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sirinvpn.conf");
    let verification = unbound_dns_verification(&DnsUpstream::Recursive, &[]).replace(
        "/etc/unbound/unbound.conf.d/sirinvpn.conf",
        path.to_str().unwrap(),
    );
    let verify = |configuration: &str| {
        fs::write(&path, configuration).unwrap();
        std::process::Command::new("/bin/sh")
            .arg("-c")
            // Trailing commands must not mask an earlier failed absence check.
            .arg(format!("set -eu\n{verification}\ntrue"))
            .status()
            .unwrap()
    };
    assert!(verify("server:\n  interface: 127.0.0.1\n").success());
    for forbidden in [
        "server:\n  local-zone: \"nas.home.\" static\n",
        "forward-zone:\n  forward-addr: 192.0.2.1@853#dns.example\n",
    ] {
        assert!(!verify(forbidden).success(), "{forbidden}");
    }
}
