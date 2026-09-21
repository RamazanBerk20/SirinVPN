use super::*;

#[derive(Serialize)]
struct DnsStatusFixture {
    #[serde(default, skip_serializing_if = "is_recursive_dns_upstream")]
    dns_upstream: DnsUpstream,
}

mod legacy_configuration_defaults_new_capability_flags_off;
mod rejects_command_shaped_hosts;
