//! Dns.

use super::*;

pub(super) fn server_dns_init_arguments(
    dns_upstream: &DnsUpstream,
    private_dns_records: &[PrivateDnsRecord],
) -> String {
    let mut arguments = match dns_upstream {
        DnsUpstream::Split { .. } => format!(
            " --dns-policy-json {}",
            shell_quote(&serde_json::to_string(dns_upstream).expect("DNS policy serializes"))
        ),
        DnsUpstream::Recursive => " --recursive-dns".to_owned(),
        DnsUpstream::DnsOverTls { endpoints } => endpoints
            .iter()
            .map(|endpoint| {
                format!(
                    " --dns-over-tls-endpoint {}",
                    shell_quote(&endpoint.to_string())
                )
            })
            .collect(),
        DnsUpstream::DnsOverHttps { endpoints } => endpoints
            .iter()
            .map(|endpoint| {
                format!(
                    " --dns-over-https-endpoint {}",
                    shell_quote(&endpoint.to_string())
                )
            })
            .collect(),
    };
    if private_dns_records.is_empty() {
        arguments.push_str(" --clear-private-dns-records");
    } else {
        for record in private_dns_records {
            arguments.push_str(&format!(
                " --private-dns-record {}",
                shell_quote(&record.to_string())
            ));
        }
    }
    arguments
}

/// Non-global IPv4 (RFC 6052 3.1): a LAN name behind a subnet route or any private answer must
/// not reach the NAT64 operator, so `respip` turns AAAA synthesized from these into NODATA
/// (`redirect` without `response-ip-data`; Unbound has no `always_nodata` for `response-ip`).
const NON_GLOBAL_IPV4: [(Ipv4Addr, u8); 7] = [
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
];

const DNS64_MODULES: &str = "  module-config: \"respip dns64 validator iterator\"";

/// DNS64 gives IPv4-only names an AAAA inside the NAT64 prefix, so members reach them over the
/// tunnel's IPv6. The prefix line is also how Repair reads back the Owner's choice.
pub(super) fn unbound_dns64_configuration(nat64_prefix: Option<Ipv6Addr>) -> String {
    nat64_prefix.map_or_else(String::new, |prefix| {
        let mut text = format!("{DNS64_MODULES}\n  dns64-prefix: {prefix}/96");
        for (network, length) in NON_GLOBAL_IPV4 {
            let mapped = Ipv6Addr::from(u128::from(prefix) | u128::from(u32::from(network)));
            text.push_str(&format!(
                "\n  response-ip: {mapped}/{} redirect",
                96 + length
            ));
        }
        text
    })
}

pub(super) fn unbound_dns64_verification(nat64_prefix: Option<Ipv6Addr>) -> String {
    let configuration = "/etc/unbound/unbound.conf.d/sirinvpn.conf";
    match nat64_prefix {
        Some(prefix) => format!(
            "grep -Fxq '{DNS64_MODULES}' {configuration} && grep -Fxq '  dns64-prefix: {prefix}/96' {configuration} || exit 1"
        ),
        // Record names cannot contain a colon, so these never match a private record.
        None => format!(
            "if grep -Fq 'module-config:' {configuration} || grep -Fq 'dns64-prefix:' {configuration}; then exit 1; fi"
        ),
    }
}

pub(super) fn installed_nat64_prefix(
    session: &Session,
    target: &SshTarget,
) -> Result<Option<Ipv6Addr>, InstallerError> {
    let output = run_privileged(
        session,
        target,
        "if [ -f /etc/unbound/unbound.conf.d/sirinvpn.conf ]; then sed -n 's|^  dns64-prefix: \\(.*\\)/96$|\\1|p' /etc/unbound/unbound.conf.d/sirinvpn.conf; fi",
    )
    .map_err(|error| phase_error("NAT64 configuration", error))?;
    match output.trim() {
        "" => Ok(None),
        text => text.parse().map(Some).map_err(|_| {
            InstallerError::Incompatible("the installed NAT64 prefix is invalid".to_owned())
        }),
    }
}

/// The VPS resolver answers every leak-test name with its tunnel address; no public resolver
/// answers this private-use zone, so a matching answer shows system DNS reached this VPS.
pub(super) fn leak_test_zone() -> String {
    format!(
        "server:\n  local-zone: \"{zone}.\" redirect\n  local-data: \"{zone}. 0 IN A {SERVER_TUNNEL_ADDRESS}\"",
        zone = sirinvpn_protocol::LEAK_TEST_DNS_ZONE
    )
}

pub(super) fn unbound_dns_configuration(
    dns_upstream: &DnsUpstream,
    private_dns_records: &[PrivateDnsRecord],
) -> (String, String) {
    if let DnsUpstream::Split { default, zones } = dns_upstream {
        let (mut server, mut forwarding) = unbound_dns_configuration(default, private_dns_records);
        if zones.iter().any(|zone| {
            matches!(
                zone.upstream,
                sirinvpn_protocol::SplitDnsUpstream::DnsOverTls { .. }
            )
        }) && !server.contains("tls-cert-bundle:")
        {
            server.push_str("\n  tls-cert-bundle: \"/etc/ssl/certs/ca-certificates.crt\"");
        }
        for zone in zones {
            let transparent = format!("  local-zone: \"{}.\" transparent", zone.suffix);
            if private_dns_records
                .iter()
                .any(|record| record.name == zone.suffix)
            {
                // A static zone would answer every other name under the
                // forwarded suffix locally; keep only its own local-data.
                server = server.replace(
                    &format!("  local-zone: \"{}.\" static", zone.suffix),
                    &transparent,
                );
            } else {
                server.push('\n');
                server.push_str(&transparent);
            }
            server.push_str(&format!("\n  private-domain: \"{}.\"", zone.suffix));
            if zone.allow_unsigned_answers {
                server.push_str(&format!("\n  domain-insecure: \"{}.\"", zone.suffix));
            }
            forwarding.push_str(&format!(
                "\n\nforward-zone:\n  name: \"{}.\"\n  forward-first: no",
                zone.suffix
            ));
            match &zone.upstream {
                sirinvpn_protocol::SplitDnsUpstream::Private { addresses } => {
                    forwarding.push_str("\n  forward-tcp-upstream: yes");
                    for address in addresses {
                        forwarding.push_str(&format!("\n  forward-addr: {address}@53"));
                    }
                }
                sirinvpn_protocol::SplitDnsUpstream::DnsOverTls { endpoints } => {
                    forwarding.push_str("\n  forward-tls-upstream: yes");
                    for endpoint in endpoints {
                        forwarding.push_str(&format!(
                            "\n  forward-addr: {}@853#{}",
                            endpoint.address, endpoint.authentication_name
                        ));
                    }
                }
            }
        }
        return (server.trim_start_matches('\n').to_owned(), forwarding);
    }
    let mut server_lines = Vec::new();
    let forwarding = match dns_upstream {
        DnsUpstream::Recursive => String::new(),
        DnsUpstream::DnsOverTls { endpoints } => {
            server_lines
                .push("  tls-cert-bundle: \"/etc/ssl/certs/ca-certificates.crt\"".to_owned());
            let forward_addresses = endpoints
                .iter()
                .map(|endpoint| {
                    format!(
                        "  forward-addr: {}@853#{}",
                        endpoint.address, endpoint.authentication_name
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            format!(
                r#"

forward-zone:
  name: "."
  forward-tls-upstream: yes
  forward-first: no
{forward_addresses}"#,
            )
        }
        DnsUpstream::DnsOverHttps { .. } => {
            server_lines.push("  do-not-query-localhost: no".to_owned());
            format!(
                r#"

forward-zone:
  name: "."
  forward-first: no
  forward-addr: 127.0.0.1@{DOH_PROXY_PORT}"#,
            )
        }
        DnsUpstream::Split { .. } => unreachable!("split policy handled above"),
    };

    let mut names = Vec::new();
    for record in private_dns_records {
        if !names.contains(&record.name) {
            names.push(record.name.clone());
            server_lines.push(format!("  local-zone: \"{}.\" static", record.name));
        }
        let record_type = if record.address.is_ipv4() {
            "A"
        } else {
            "AAAA"
        };
        server_lines.push(format!(
            "  local-data: \"{}. 60 IN {record_type} {}\"",
            record.name, record.address
        ));
    }

    (server_lines.join("\n"), forwarding)
}

pub(super) fn unbound_dns_verification(
    dns_upstream: &DnsUpstream,
    private_dns_records: &[PrivateDnsRecord],
) -> String {
    let configuration = "/etc/unbound/unbound.conf.d/sirinvpn.conf";
    if let DnsUpstream::Split { default, zones } = dns_upstream {
        let (server, forwarding) = unbound_dns_configuration(dns_upstream, private_dns_records);
        let count = zones.len() + usize::from(!default.is_recursive());
        // POSIX sh only: the installer does not install python3. Quoted case
        // patterns match the multi-line blocks literally.
        return format!(
            r#"split_dns_configuration=$(cat {configuration})
for split_dns_expected in {server} {forwarding}; do
  case $split_dns_configuration in
    *"$split_dns_expected"*) ;;
    *) echo 'split DNS configuration differs from requested policy' >&2; exit 1 ;;
  esac
done
[ "$(grep -Fc 'forward-zone:' {configuration} || true)" -eq {count} ]
if grep -Fq 'forward-first: yes' {configuration}; then
  echo 'split DNS fallback is forbidden' >&2
  exit 1
fi"#,
            server = shell_quote(&server),
            forwarding = shell_quote(&forwarding),
        );
    }
    // These lines run under `set -e`, which ignores a failing `! command`; absence checks
    // therefore exit explicitly.
    let upstream_checks = match dns_upstream {
        DnsUpstream::Recursive => format!(
            r#"if grep -Fq 'forward-tls-upstream:' {configuration}; then exit 1; fi
if grep -Fq 'forward-addr:' {configuration}; then exit 1; fi
if grep -Fq '  do-not-query-localhost: no' {configuration}; then exit 1; fi"#
        ),
        DnsUpstream::DnsOverTls { endpoints } => {
            let address_checks = endpoints
                .iter()
                .map(|endpoint| {
                    format!(
                        "grep -Fxq {} {configuration}",
                        shell_quote(&format!(
                            "  forward-addr: {}@853#{}",
                            endpoint.address, endpoint.authentication_name
                        ))
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            format!(
                r#"grep -Fxq '  tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"' {configuration}
grep -Fxq '  forward-tls-upstream: yes' {configuration}
grep -Fxq '  forward-first: no' {configuration}
if grep -Fq '  forward-first: yes' {configuration}; then exit 1; fi
[ "$(grep -Fc '  forward-addr: ' {configuration} || true)" -eq {endpoint_count} ]
{address_checks}"#,
                endpoint_count = endpoints.len(),
            )
        }
        DnsUpstream::DnsOverHttps { .. } => format!(
            r#"grep -Fxq '  do-not-query-localhost: no' {configuration}
grep -Fxq '  forward-first: no' {configuration}
grep -Fxq '  forward-addr: 127.0.0.1@{DOH_PROXY_PORT}' {configuration}
[ "$(grep -Fc '  forward-addr: ' {configuration} || true)" -eq 1 ]
if grep -Fq '  forward-tls-upstream:' {configuration}; then exit 1; fi
if grep -Fq '  tls-cert-bundle:' {configuration}; then exit 1; fi"#,
        ),
        DnsUpstream::Split { .. } => unreachable!("split policy handled above"),
    };
    if private_dns_records.is_empty() {
        return format!(
            r#"{upstream_checks}
if grep -Fq '  local-zone: ' {configuration}; then exit 1; fi
if grep -Fq '  local-data: ' {configuration}; then exit 1; fi"#
        );
    }

    let mut names = Vec::new();
    let mut record_checks = Vec::new();
    for record in private_dns_records {
        if !names.contains(&record.name) {
            names.push(record.name.clone());
            record_checks.push(format!(
                "grep -Fxq {} {configuration}",
                shell_quote(&format!("  local-zone: \"{}.\" static", record.name))
            ));
        }
        let record_type = if record.address.is_ipv4() {
            "A"
        } else {
            "AAAA"
        };
        record_checks.push(format!(
            "grep -Fxq {} {configuration}",
            shell_quote(&format!(
                "  local-data: \"{}. 60 IN {record_type} {}\"",
                record.name, record.address
            ))
        ));
    }
    format!(
        r#"{upstream_checks}
[ "$(grep -Fc '  local-zone: ' {configuration} || true)" -eq {zone_count} ]
[ "$(grep -Fc '  local-data: ' {configuration} || true)" -eq {record_count} ]
{record_checks}"#,
        zone_count = names.len(),
        record_count = private_dns_records.len(),
        record_checks = record_checks.join("\n"),
    )
}
