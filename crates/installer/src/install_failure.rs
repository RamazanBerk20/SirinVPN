//! Fixed installer progress markers identify failures without exposing SSH output.

const PREFIX: &str = "SIRINVPN_INSTALL_STEP=";

const OWNER_PREFIX: &str = "SIRINVPN_TRANSACTION_OWNER=";

#[derive(Debug, thiserror::Error)]
#[error("The VPS operation failed while {step} (exit {exit_status}).{holder}")]
pub(super) struct InstallFailure {
    step: &'static str,
    exit_status: i32,
    holder: String,
}

impl InstallFailure {
    pub(super) fn from_output(output: &[u8], exit_status: i32) -> Option<Self> {
        if !(1..=255).contains(&exit_status) {
            return None;
        }
        let marker = std::str::from_utf8(output)
            .ok()?
            .lines()
            .filter_map(|line| line.strip_prefix(PREFIX))
            .next_back()?;
        let step = match marker {
            "recovery" => "checking interrupted maintenance",
            "guards" => "checking maintenance locks",
            "staged_server" => "validating the staged server component",
            "dependencies" => "checking required system packages",
            "ports" => "checking service port ownership",
            "snapshot" => "saving the existing VPS configuration",
            "recovery_guard" => "arming configuration recovery",
            "accounts" => "checking the service account",
            "server_files" => "installing the server files",
            "initialize" => "validating and initializing the existing server identity",
            "permissions" => "applying server file permissions",
            "network_configuration" => "writing VPN network configuration",
            "dns_configuration" => "writing private DNS configuration",
            "dns_validation" => "validating the private DNS configuration",
            "service_configuration" => "writing service configuration",
            "service_registration" => "registering VPS services",
            "restart_network" => "restarting the VPN network service",
            "restart_firewall" => "restarting the VPN firewall service",
            "restart_dns_proxy" => "updating the private DNS proxy service",
            "restart_dns" => "restarting the private DNS resolver",
            "restart_server" => "restarting the VPS management service",
            "busy" => "waiting for another device's maintenance transaction",
            _ => return None,
        };
        let holder = if marker == "busy" {
            // Only a 16-digit hex certificate label is shown; anything else is dropped.
            let owner = std::str::from_utf8(output)
                .ok()?
                .lines()
                .filter_map(|line| line.strip_prefix(OWNER_PREFIX))
                .next_back()
                .filter(|owner| {
                    owner.len() == 16
                        && owner
                            .bytes()
                            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                })
                .map_or_else(String::new, |owner| {
                    format!(" by the Owner certificate {owner}")
                });
            format!(
                " A transaction started{owner} is in progress on this VPS; it commits or rolls back automatically within 5 minutes, then retry."
            )
        } else {
            String::new()
        };
        Some(Self {
            step,
            exit_status,
            holder,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_fixed_step_names_can_reach_the_error() {
        let output = b"untrusted output\nSIRINVPN_INSTALL_STEP=dependencies\nSIRINVPN_INSTALL_STEP=initialize\nsensitive value\n";
        let error = InstallFailure::from_output(output, 1).unwrap();
        assert_eq!(
            error.to_string(),
            "The VPS operation failed while validating and initializing the existing server identity (exit 1)."
        );
        assert!(!error.to_string().contains("sensitive"));
        assert!(InstallFailure::from_output(b"SIRINVPN_INSTALL_STEP=secret-value\n", 1).is_none());
        assert!(
            InstallFailure::from_output(b"prefix SIRINVPN_INSTALL_STEP=initialize\n", 1).is_none()
        );
        assert!(InstallFailure::from_output(b"SIRINVPN_INSTALL_STEP=initialize\n", 0).is_none());
    }

    #[test]
    fn a_busy_vps_names_only_a_valid_owner_label() {
        let busy = |owner: &str| {
            InstallFailure::from_output(
                format!("SIRINVPN_TRANSACTION_OWNER={owner}\nSIRINVPN_INSTALL_STEP=busy\n")
                    .as_bytes(),
                75,
            )
            .unwrap()
            .to_string()
        };
        let named = busy("0123456789abcdef");
        assert!(
            named.contains("by the Owner certificate 0123456789abcdef"),
            "{named}"
        );
        assert!(named.contains("rolls back automatically within 5 minutes"));
        let unnamed = busy("$(reboot)");
        assert!(!unnamed.contains("reboot") && !unnamed.contains("certificate"));
    }

    #[test]
    fn phase_errors_preserve_safe_step_details_in_all_build_profiles() {
        let error =
            InstallFailure::from_output(b"SIRINVPN_INSTALL_STEP=dns_validation\n", 2).unwrap();
        let error = crate::ssh::phase_error("server configuration", error.into()).to_string();
        assert!(error.contains("validating the private DNS configuration (exit 2)"));
        assert!(!error.contains("Debug-only"));
    }
}
