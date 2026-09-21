//! Fixed installer progress markers identify failures without exposing SSH output.

const PREFIX: &str = "SIRINVPN_INSTALL_STEP=";

#[derive(Debug, thiserror::Error)]
#[error("The VPS operation failed while {step} (exit {exit_status}).")]
pub(super) struct InstallFailure {
    step: &'static str,
    exit_status: i32,
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
            "dependencies" => "checking required Debian packages",
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
            _ => return None,
        };
        Some(Self { step, exit_status })
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
    fn phase_errors_preserve_safe_step_details_in_all_build_profiles() {
        let error =
            InstallFailure::from_output(b"SIRINVPN_INSTALL_STEP=dns_validation\n", 2).unwrap();
        let error = crate::ssh::phase_error("server configuration", error.into()).to_string();
        assert!(error.contains("validating the private DNS configuration (exit 2)"));
        assert!(!error.contains("Debug-only"));
    }
}
