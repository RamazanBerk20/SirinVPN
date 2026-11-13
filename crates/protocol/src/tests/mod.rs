use super::*;

#[derive(Serialize)]
struct DnsStatusFixture {
    #[serde(default, skip_serializing_if = "is_recursive_dns_upstream")]
    dns_upstream: DnsUpstream,
}

mod device_platform_and_blocking_flag_are_optional;
mod endpoint_handoff_reads_legacy_profile_fields;
mod https_cdn_mode_is_opt_in_and_invisible_when_off;
mod legacy_configuration_defaults_new_capability_flags_off;
mod named_join_codes_and_invitation_issuers_are_optional;
mod rejects_command_shaped_hosts;
