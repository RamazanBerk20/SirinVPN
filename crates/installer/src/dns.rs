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
            if !private_dns_records
                .iter()
                .any(|record| record.name == zone.suffix)
            {
                server.push_str(&format!("\n  local-zone: \"{}.\" transparent", zone.suffix));
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
        let expected = STANDARD.encode(
            serde_json::to_vec(&(server, forwarding)).expect("DNS configuration serializes"),
        );
        let count = zones.len() + usize::from(!default.is_recursive());
        return format!(
            r#"python3 - <<'SIRINVPN_VERIFY_SPLIT_DNS'
import base64, json, pathlib
actual = pathlib.Path('{configuration}').read_text()
server, forwarding = json.loads(base64.b64decode('{expected}'))
assert server in actual and forwarding in actual, 'split DNS configuration differs from requested policy'
assert actual.count('forward-zone:') == {count}
assert 'forward-first: yes' not in actual, 'split DNS fallback is forbidden'
SIRINVPN_VERIFY_SPLIT_DNS"#
        );
    }
    let upstream_checks = match dns_upstream {
        DnsUpstream::Recursive => format!(
            r#"! grep -Fq 'forward-tls-upstream:' {configuration}
! grep -Fq 'forward-addr:' {configuration}
! grep -Fq '  do-not-query-localhost: no' {configuration}"#
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
! grep -Fq '  forward-first: yes' {configuration}
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
! grep -Fq '  forward-tls-upstream:' {configuration}
! grep -Fq '  tls-cert-bundle:' {configuration}"#,
        ),
        DnsUpstream::Split { .. } => unreachable!("split policy handled above"),
    };
    if private_dns_records.is_empty() {
        return format!(
            r#"{upstream_checks}
! grep -Fq '  local-zone: ' {configuration}
! grep -Fq '  local-data: ' {configuration}"#
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
