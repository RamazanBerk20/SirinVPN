use super::*;

#[derive(Args)]
pub(crate) struct TransportArguments {
    #[arg(long)]
    pub(crate) public_host: Option<String>,
    #[arg(long, conflicts_with = "clear_alternate_hosts")]
    pub(crate) alternate_host: Vec<String>,
    #[arg(long)]
    pub(crate) clear_alternate_hosts: bool,
    #[arg(long)]
    pub(crate) wireguard_port: Option<u16>,
    #[arg(long)]
    pub(crate) obfuscated_udp_port: Option<u16>,
    /// TCP and TLS share an authenticated listener; QUIC uses the same port number over UDP.
    #[arg(long)]
    pub(crate) tcp_tls_port: Option<u16>,
    /// `true` answers QUIC (HTTP/3) on UDP at the TCP/TLS port number; Obfuscated UDP then
    /// needs another port. Omitted, a repair keeps the server's current setting.
    #[arg(long)]
    pub(crate) quic: Option<bool>,
    #[arg(long, conflicts_with = "disable_https")]
    pub(crate) https_server_name: Option<String>,
    #[arg(long, conflicts_with = "disable_https")]
    pub(crate) https_path: Option<String>,
    /// `true` when a CDN such as Cloudflare proxies the HTTPS hostname to this VPS.
    #[arg(long, conflicts_with = "disable_https")]
    pub(crate) https_cdn: Option<bool>,
    /// Absolute PEM certificate-chain path already present on the VPS.
    #[arg(
        long,
        requires = "https_private_key_path",
        conflicts_with = "disable_https"
    )]
    pub(crate) https_certificate_path: Option<String>,
    /// Absolute matching private-key path already present on the VPS.
    #[arg(
        long,
        requires = "https_certificate_path",
        conflicts_with = "disable_https"
    )]
    pub(crate) https_private_key_path: Option<String>,
    #[arg(long)]
    pub(crate) disable_https: bool,
}

impl TransportArguments {
    pub(crate) fn requested(
        &self,
        profile: Option<&ServerProfile>,
    ) -> Result<Option<sirinvpn_installer::TransportSetup>> {
        if self.wireguard_port.is_none()
            && self.public_host.is_none()
            && self.alternate_host.is_empty()
            && !self.clear_alternate_hosts
            && self.obfuscated_udp_port.is_none()
            && self.tcp_tls_port.is_none()
            && self.quic.is_none()
            && self.https_server_name.is_none()
            && self.https_path.is_none()
            && self.https_cdn.is_none()
            && self.https_certificate_path.is_none()
            && !self.disable_https
        {
            return Ok(None);
        }
        let mut setup = profile
            .map(sirinvpn_installer::TransportSetup::from_profile)
            .unwrap_or_default();
        if let Some(host) = &self.public_host {
            setup.public_host = Some(host.clone());
        }
        if !self.alternate_host.is_empty() || self.clear_alternate_hosts {
            setup.alternate_endpoint_hosts = self.alternate_host.clone();
        }
        if let Some(port) = self.wireguard_port {
            setup.wireguard_port = port;
        }
        if let Some(port) = self.obfuscated_udp_port {
            setup.obfuscated_udp_port = port;
        }
        if let Some(port) = self.tcp_tls_port {
            setup.tcp_tls_port = port;
        }
        if let Some(quic) = self.quic {
            setup.quic = quic;
            if quic
                && self.obfuscated_udp_port.is_none()
                && setup.obfuscated_udp_port == setup.tcp_tls_port
            {
                setup.obfuscated_udp_port = sirinvpn_protocol::DEFAULT_OBFUSCATED_UDP_PORT;
                eprintln!(
                    "Note: Obfuscated UDP moves to port {} so QUIC can answer on UDP {}.",
                    setup.obfuscated_udp_port, setup.tcp_tls_port
                );
            }
        }
        if let Some(name) = &self.https_server_name {
            if self.https_cdn.is_none() && setup.https.as_ref().is_some_and(|https| https.cdn) {
                eprintln!("Note: --https-server-name without --https-cdn true turns CDN mode off.");
            }
            setup.https = Some(sirinvpn_protocol::HttpsTransport {
                server_name: name.clone(),
                path: self.https_path.clone().unwrap_or_else(|| "/connect".into()),
                cdn: self.https_cdn.unwrap_or(false),
            });
        } else if self.https_path.is_some() || self.https_cdn.is_some() {
            let https = setup
                .https
                .as_mut()
                .context("specify --https-server-name to enable HTTPS first")?;
            if let Some(path) = &self.https_path {
                https.path = path.clone();
            }
            if let Some(cdn) = self.https_cdn {
                https.cdn = cdn;
            }
        }
        setup.https_certificate_path = self.https_certificate_path.clone();
        setup.https_private_key_path = self.https_private_key_path.clone();
        setup.disable_https = self.disable_https;
        if self.disable_https {
            setup.https = None;
        }
        // Cloudflare proxies HTTPS only on these ports; other CDNs may differ, so warn only.
        if setup.https.as_ref().is_some_and(|https| https.cdn)
            && ![443, 2053, 2083, 2087, 2096].contains(&setup.tcp_tls_port)
        {
            eprintln!(
                "Note: Cloudflare proxies HTTPS only on ports 443, 2053, 2083, 2087 and 2096. Check that your CDN proxies TCP/TLS port {}.",
                setup.tcp_tls_port
            );
        }
        if !setup.quic {
            eprintln!("Note: QUIC (HTTP/3) stays off. Pass --quic true to turn it on.");
        }
        setup.validate()?;
        Ok(Some(setup))
    }
}
