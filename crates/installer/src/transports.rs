use super::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransportSetup {
    pub public_host: Option<String>,
    pub alternate_endpoint_hosts: Vec<String>,
    pub wireguard_port: u16,
    pub obfuscated_udp_port: u16,
    pub tcp_tls_port: u16,
    pub https: Option<sirinvpn_protocol::HttpsTransport>,
    pub https_certificate_path: Option<String>,
    pub https_private_key_path: Option<String>,
    pub disable_https: bool,
}

impl Default for TransportSetup {
    fn default() -> Self {
        Self {
            public_host: None,
            alternate_endpoint_hosts: Vec::new(),
            wireguard_port: DEFAULT_WIREGUARD_PORT,
            obfuscated_udp_port: DEFAULT_OBFUSCATED_UDP_PORT,
            tcp_tls_port: DEFAULT_TCP_FALLBACK_PORT,
            https: None,
            https_certificate_path: None,
            https_private_key_path: None,
            disable_https: false,
        }
    }
}

impl TransportSetup {
    pub fn from_profile(profile: &ServerProfile) -> Self {
        Self {
            public_host: Some(profile.endpoint.host.clone()),
            alternate_endpoint_hosts: profile.alternate_endpoint_hosts.clone(),
            wireguard_port: profile.endpoint.wireguard_port,
            obfuscated_udp_port: profile
                .obfuscated_udp
                .as_ref()
                .map_or(DEFAULT_OBFUSCATED_UDP_PORT, |endpoint| endpoint.port),
            tcp_tls_port: profile
                .tcp_fallback
                .as_ref()
                .map_or(DEFAULT_TCP_FALLBACK_PORT, |endpoint| endpoint.port),
            https: profile
                .tls_like
                .as_ref()
                .and_then(|endpoint| endpoint.https.clone()),
            ..Self::default()
        }
    }

    pub fn validate(&self) -> Result<(), InstallerError> {
        let invalid = |message: &str| InstallerError::InvalidInput(message.into());
        if self
            .public_host
            .as_ref()
            .is_some_and(|host| validate_host(host).is_err() || host.trim() != host)
            || !sirinvpn_protocol::valid_alternate_endpoint_hosts(
                self.public_host.as_deref().unwrap_or(""),
                &self.alternate_endpoint_hosts,
            )
        {
            return Err(invalid(
                "Choose a valid public hostname or IP address and up to three distinct alternate addresses.",
            ));
        }
        if [
            self.wireguard_port,
            self.obfuscated_udp_port,
            self.tcp_tls_port,
        ]
        .iter()
        .any(|port| {
            *port == 0 || *port == 53 || *port == DOH_PROXY_PORT || *port == DEFAULT_MANAGEMENT_PORT
        }) || self.wireguard_port == self.obfuscated_udp_port
            || self.tcp_tls_port == self.wireguard_port
        {
            return Err(invalid(
                "Choose nonzero transport ports outside the private DNS/management ports; the direct UDP port must differ from the wrapped transports.",
            ));
        }
        if self.https.as_ref().is_some_and(|https| !https.is_valid())
            || (self.disable_https && self.https.is_some())
        {
            return Err(invalid(
                "HTTPS needs a valid DNS hostname and a path such as /connect.",
            ));
        }
        if self.https_certificate_path.is_some() != self.https_private_key_path.is_some()
            || (self.https_certificate_path.is_some() && self.https.is_none())
        {
            return Err(invalid(
                "A custom HTTPS certificate requires its matching key path on the VPS and an HTTPS hostname.",
            ));
        }
        for path in self
            .https_certificate_path
            .iter()
            .chain(self.https_private_key_path.iter())
        {
            if !Path::new(path).is_absolute()
                || path.len() > 4_096
                || path.chars().any(char::is_control)
            {
                return Err(invalid(
                    "Certificate and key paths must be absolute paths on the VPS.",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn port_arguments(&self) -> String {
        format!(
            " --wireguard-port {} --obfuscated-udp-port {} --tcp-fallback-port {} --tls-like-port {}",
            self.wireguard_port, self.obfuscated_udp_port, self.tcp_tls_port, self.tcp_tls_port
        )
    }
    pub(super) fn init_arguments(&self) -> String {
        let mut arguments = self.port_arguments();
        arguments.push_str(" --update-transport-ports");
        if let Some(https) = &self.https {
            arguments.push_str(&format!(
                " --https-server-name {} --https-path {}",
                shell_quote(&https.server_name),
                shell_quote(&https.path)
            ));
        }
        if let (Some(certificate), Some(key)) =
            (&self.https_certificate_path, &self.https_private_key_path)
        {
            arguments.push_str(&format!(
                " --https-certificate {} --https-private-key {}",
                shell_quote(certificate),
                shell_quote(key)
            ));
        }
        if self.disable_https {
            arguments.push_str(" --disable-https");
        }
        arguments
    }

    pub(super) fn endpoint_arguments(
        &self,
        target_host: &str,
        previous: Option<&ServerProfile>,
    ) -> String {
        let mut arguments = format!(
            " --public-host {}",
            shell_quote(self.public_host.as_deref().unwrap_or(target_host))
        );
        if let Some(profile) = previous {
            arguments.push_str(&format!(
                " --previous-public-host {}",
                shell_quote(&profile.endpoint.host)
            ));
        }
        for host in &self.alternate_endpoint_hosts {
            arguments.push_str(&format!(" --alternate-host {}", shell_quote(host)));
        }
        arguments
    }
}

pub(super) fn bootstrap_matches_transport(
    bootstrap: &BootstrapOutput,
    requested: &TransportSetup,
) -> bool {
    bootstrap.wireguard_port == requested.wireguard_port
        && bootstrap
            .obfuscated_udp
            .as_ref()
            .is_some_and(|endpoint| endpoint.port == requested.obfuscated_udp_port)
        && bootstrap
            .tcp_fallback
            .as_ref()
            .is_some_and(|endpoint| endpoint.port == requested.tcp_tls_port)
        && bootstrap.tls_like.as_ref().is_some_and(|endpoint| {
            endpoint.port == requested.tcp_tls_port
                && match (&requested.https, requested.disable_https) {
                    (Some(expected), _) => endpoint.https.as_ref() == Some(expected),
                    (None, true) => endpoint.https.is_none(),
                    _ => true,
                }
        })
}
