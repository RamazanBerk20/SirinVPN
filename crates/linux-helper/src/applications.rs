//! Launched processes share a VPN-only network stack. No executable or activity
//! history is retained. Only explicit launches create a namespace; the constrained
//! reconnect service never needs mount or namespace-administration capabilities.
use super::*;
use std::os::unix::fs::MetadataExt;

mod firewall;
mod launch;
mod routes;
mod runtime;

pub(super) const NAMESPACE: &str = "sirinvpn-apps";
pub(super) const HOST_LINK: &str = "svapp0";
const PEER_LINK: &str = "svapp1";
const HOST4: &str = "169.254.83.1";
const APP4: &str = "169.254.83.2";
const HOST6: &str = "fd73:6972:696e:ffff::1";
const APP6: &str = "fd73:6972:696e:ffff::2";
const DNS_BLOCK_PRIORITY: &str = "9991";
const FALLBACK_BLOCK_PRIORITY: &str = "10002";
const CONFIG_OWNER: &str = "SirinVPN application DNS configuration v1\n";

pub(super) fn ipv6_forwarding_available() -> bool {
    // Use the interface-level exception on newer kernels. Older kernels use
    // IPv6 routing only if the host already enabled it; never change it globally.
    Path::new("/proc/sys/net/ipv6/conf/default/force_forwarding").exists()
        || fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding")
            .is_ok_and(|value| value.trim() == "1")
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicationNetwork {
    schema_version: u16,
    server_id: ServerId,
    uid: u32,
    dns_address: Ipv4Addr,
    client_address: Ipv4Addr,
    client_ipv6_address: Option<Ipv6Addr>,
    allow_lan: bool,
}

impl ApplicationNetwork {
    fn matches(&self, request: &TunnelConnectRequest) -> bool {
        self.same_namespace(request)
            && self.client_address == request.client_address
            && self.client_ipv6_address == request.client_ipv6_address
    }

    fn same_namespace(&self, request: &TunnelConnectRequest) -> bool {
        self.schema_version == 1
            && self.uid != 0
            && self.server_id == request.server_id
            && self.dns_address == request.dns_address
            && self.allow_lan == request.routing.allow_lan
    }
}

impl<R: CommandRunner> LinuxNetworkHelper<R> {
    fn application_path(&self) -> PathBuf {
        self.runtime_directory.join("application-network.json")
    }

    fn read_application_network(&self) -> Result<ApplicationNetwork> {
        let bytes = read_owned_file(&self.application_path(), 4096)?;
        let state: ApplicationNetwork = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(
            state.schema_version == 1 && state.uid != 0,
            "invalid application network"
        );
        Ok(state)
    }

    pub(super) fn application_guard_is_verified(&self, request: &TunnelConnectRequest) -> bool {
        self.runner
            .output("nft", &["-j", "list", "table", "inet", firewall::TABLE])
            .ok()
            .and_then(|bytes| enforcement::normalize_guard(&bytes))
            .is_some_and(|objects| objects == firewall::objects(request))
    }

    pub(super) fn application_configuration_exists(&self, request: &TunnelConnectRequest) -> bool {
        self.application_guard_is_verified(request)
            && self.application_rules_verified(request)
            && self.application_forwarding_verified(request)
            && (!self.application_path().exists()
                || (self
                    .read_application_network()
                    .is_ok_and(|state| state.matches(request))
                    && self.application_link_is_up()))
    }

    fn application_link_is_up(&self) -> bool {
        self.runner
            .output("ip", &["-j", "link", "show", "dev", HOST_LINK])
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|value| value.as_array().cloned())
            .is_some_and(|links| {
                links.len() == 1
                    && links[0]["flags"]
                        .as_array()
                        .is_some_and(|flags| flags.iter().any(|flag| flag == "UP"))
            })
    }

    fn application_fallback_rule_exists(&self, family: &str) -> bool {
        self.application_rule_matches(family, FALLBACK_BLOCK_PRIORITY, Some(HOST_LINK), None, None)
    }

    pub(super) fn apply_application_routing(&self, request: &TunnelConnectRequest) -> Result<()> {
        // Keep the link down until the route and firewall transactions are complete.
        self.suspend_applications()?;
        let objects = firewall::objects(request);
        let commands = firewall::transaction(&objects);
        self.runner.run(
            "nft",
            &["-j", "-f", "-"],
            Some(&serde_json::to_vec(
                &serde_json::json!({"nftables":commands}),
            )?),
        )?;
        anyhow::ensure!(
            self.application_guard_is_verified(request),
            "application guard verification failed"
        );
        // Per-interface forwarding avoids changing the host's global forwarding policy.
        self.runner.run(
            "sysctl",
            &[
                "-q",
                "-w",
                &format!("net.ipv4.conf.{INTERFACE_NAME}.forwarding=1"),
                &format!("net.ipv4.conf.{INTERFACE_NAME}.rp_filter=2"),
            ],
            None,
        )?;
        if request.client_ipv6_address.is_some() && ipv6_forwarding_available() {
            self.enable_ipv6_forwarding(INTERFACE_NAME)?;
            self.runner.run(
                "sysctl",
                &[
                    "-q",
                    "-w",
                    &format!("net.ipv6.conf.{INTERFACE_NAME}.forwarding=1"),
                ],
                None,
            )?;
        }
        if self.application_path().exists() {
            let mut network = self.read_application_network()?;
            anyhow::ensure!(
                network.same_namespace(request),
                "application session changed; disconnect first"
            );
            // Key rotation may allocate a new tunnel address. The namespace's
            // private addresses and DNS stay fixed; change only its VPN SNAT binding.
            if request.client_ipv6_address.is_some() && ipv6_forwarding_available() {
                self.enable_ipv6_forwarding(HOST_LINK)?;
            }
            network.client_address = request.client_address;
            network.client_ipv6_address = request.client_ipv6_address;
            write_owned_file(
                &self.application_path(),
                &serde_json::to_vec(&network)?,
                0o600,
            )?;
            self.runner.run(
                "ip",
                &[
                    "link",
                    "set",
                    "dev",
                    HOST_LINK,
                    "mtu",
                    &request.mtu.to_string(),
                    "up",
                ],
                None,
            )?;
        }
        Ok(())
    }

    fn enable_ipv6_forwarding(&self, link: &str) -> Result<()> {
        if Path::new(&format!("/proc/sys/net/ipv6/conf/{link}/force_forwarding")).exists() {
            self.runner.run(
                "sysctl",
                &[
                    "-q",
                    "-w",
                    &format!("net.ipv6.conf.{link}.force_forwarding=1"),
                ],
                None,
            )?;
        }
        Ok(())
    }

    pub(super) fn apply_application_exceptions(
        &self,
        request: &TunnelConnectRequest,
    ) -> Result<()> {
        let dns = format!("{}/32", request.dns_address);
        // The desktop's authenticated management connection can still reach its VPS.
        self.runner.run(
            "ip",
            &[
                "-4",
                "rule",
                "add",
                "to",
                &dns,
                "table",
                ROUTING_TABLE,
                "priority",
                DNS_RULE_PRIORITY,
            ],
            None,
        )?;
        self.runner.run(
            "ip",
            &[
                "-4",
                "rule",
                "add",
                "iif",
                HOST_LINK,
                "to",
                &dns,
                "prohibit",
                "priority",
                DNS_BLOCK_PRIORITY,
            ],
            None,
        )?;
        for family in ["-4", "-6"] {
            self.runner.run(
                "ip",
                &[
                    family,
                    "rule",
                    "add",
                    "iif",
                    HOST_LINK,
                    "prohibit",
                    "priority",
                    FALLBACK_BLOCK_PRIORITY,
                ],
                None,
            )?;
        }
        if request.routing.allow_lan {
            for (index, route) in IPV4_LAN_ROUTES.iter().enumerate() {
                let priority = (LAN_RULE_PRIORITY_START + 1 + index as u16).to_string();
                self.runner.run(
                    "ip",
                    &[
                        "-4", "rule", "add", "iif", HOST_LINK, "to", route, "table", "main",
                        "priority", &priority,
                    ],
                    None,
                )?;
            }
        }
        Ok(())
    }

    pub(super) fn suspend_applications(&self) -> Result<(), HelperError> {
        if self.application_path().exists() {
            self.read_application_network()
                .map_err(|_| HelperError::InvalidState)?;
            if self
                .runner
                .succeeds("ip", &["link", "show", "dev", HOST_LINK])
            {
                self.runner
                    .run("ip", &["link", "set", "dev", HOST_LINK, "down"], None)
                    .map_err(|_| HelperError::NetworkOperationFailed)?;
                if self.application_link_is_up() {
                    return Err(HelperError::NetworkOperationFailed);
                }
            }
        }
        Ok(())
    }

    pub(super) fn cleanup_application_routes(&self, state: Option<&RuntimeState>) {
        let Some(state) =
            state.filter(|s| s.routing.mode == TunnelRoutingMode::SelectedApplications)
        else {
            return;
        };
        for family in ["-4", "-6"] {
            let _ = self.runner.run(
                "ip",
                &[
                    family,
                    "rule",
                    "delete",
                    "iif",
                    HOST_LINK,
                    "table",
                    ROUTING_TABLE,
                    "priority",
                    RULE_TUNNEL_PRIORITY,
                ],
                None,
            );
            let _ = self.runner.run(
                "ip",
                &[
                    family,
                    "rule",
                    "delete",
                    "iif",
                    HOST_LINK,
                    "prohibit",
                    "priority",
                    FALLBACK_BLOCK_PRIORITY,
                ],
                None,
            );
        }
        if let Some(address) = state.dns_address {
            let dns = format!("{address}/32");
            let _ = self.runner.run(
                "ip",
                &[
                    "-4",
                    "rule",
                    "delete",
                    "to",
                    &dns,
                    "table",
                    ROUTING_TABLE,
                    "priority",
                    DNS_RULE_PRIORITY,
                ],
                None,
            );
            let _ = self.runner.run(
                "ip",
                &[
                    "-4",
                    "rule",
                    "delete",
                    "iif",
                    HOST_LINK,
                    "to",
                    &dns,
                    "prohibit",
                    "priority",
                    DNS_BLOCK_PRIORITY,
                ],
                None,
            );
        }
        if state.routing.allow_lan {
            for (index, route) in IPV4_LAN_ROUTES.iter().enumerate() {
                let priority = (LAN_RULE_PRIORITY_START + 1 + index as u16).to_string();
                let _ = self.runner.run(
                    "ip",
                    &[
                        "-4", "rule", "delete", "iif", HOST_LINK, "to", route, "table", "main",
                        "priority", &priority,
                    ],
                    None,
                );
            }
        }
    }

    pub(super) fn destroy_applications(&self) -> Result<(), HelperError> {
        if !self.application_path().exists()
            && !self
                .read_state()
                .is_ok_and(|state| state.routing.mode == TunnelRoutingMode::SelectedApplications)
            && !self
                .runner
                .succeeds("nft", &["list", "table", "inet", firewall::TABLE])
        {
            return Ok(());
        }
        let action = || -> Result<()> {
            if self.application_path().exists() {
                self.read_application_network()?;
                self.suspend_applications()?;
                if self
                    .runner
                    .succeeds("ip", &["link", "show", "dev", HOST_LINK])
                {
                    self.runner
                        .run("ip", &["link", "delete", "dev", HOST_LINK], None)?;
                    anyhow::ensure!(
                        !self
                            .runner
                            .succeeds("ip", &["link", "show", "dev", HOST_LINK]),
                        "application link still exists"
                    );
                }
                if self.namespace_exists()? {
                    self.runner
                        .run("ip", &["netns", "delete", NAMESPACE], None)?;
                }
                anyhow::ensure!(
                    !self.namespace_exists()?,
                    "application namespace still named"
                );
                self.remove_application_dns()?;
                remove_file_if_exists(&self.application_path())?;
            }
            // Losing metadata is not permission to remove a guard from a live
            // application link. Inspect every link, and retain the guard on error.
            let bytes = self.runner.output("ip", &["-j", "link", "show"])?;
            let links: Vec<serde_json::Value> = serde_json::from_slice(&bytes)?;
            anyhow::ensure!(
                !links.iter().any(|link| link["ifname"] == HOST_LINK),
                "an application link still exists"
            );
            if self
                .runner
                .succeeds("nft", &["list", "table", "inet", firewall::TABLE])
            {
                self.runner
                    .run("nft", &["delete", "table", "inet", firewall::TABLE], None)?;
            }
            Ok(())
        };
        action().map_err(|_| HelperError::NetworkOperationFailed)
    }

    fn namespace_exists(&self) -> Result<bool> {
        let bytes = self.runner.output("ip", &["netns", "list"])?;
        Ok(std::str::from_utf8(&bytes)?
            .lines()
            .any(|line| line.split_whitespace().next() == Some(NAMESPACE)))
    }

    fn prepare_application_network(&self, request: &TunnelConnectRequest, uid: u32) -> Result<()> {
        if self.application_path().exists() {
            let state = self.read_application_network()?;
            anyhow::ensure!(
                state.uid == uid && state.matches(request),
                "application network belongs to another session or user"
            );
            anyhow::ensure!(
                self.namespace_exists()? && self.application_configuration_exists(request),
                "application network needs a new connection"
            );
            return Ok(());
        }
        anyhow::ensure!(
            !self.namespace_exists()?,
            "application namespace is already in use"
        );
        for link in [HOST_LINK, PEER_LINK] {
            anyhow::ensure!(
                !self.runner.succeeds("ip", &["link", "show", "dev", link]),
                "application link name is already in use"
            );
        }
        self.ensure_application_address_space()?;
        let state = ApplicationNetwork {
            schema_version: 1,
            server_id: request.server_id,
            uid,
            dns_address: request.dns_address,
            client_address: request.client_address,
            client_ipv6_address: request.client_ipv6_address,
            allow_lan: request.routing.allow_lan,
        };
        self.write_application_dns(request.dns_address)?;
        write_owned_file(
            &self.application_path(),
            &serde_json::to_vec(&state)?,
            0o600,
        )?;
        let action = || -> Result<()> {
            self.runner.run("ip", &["netns", "add", NAMESPACE], None)?;
            self.runner.run(
                "ip",
                &[
                    "link", "add", HOST_LINK, "type", "veth", "peer", "name", PEER_LINK, "netns",
                    NAMESPACE,
                ],
                None,
            )?;
            self.runner.run(
                "ip",
                &["address", "add", &format!("{HOST4}/30"), "dev", HOST_LINK],
                None,
            )?;
            self.runner.run(
                "ip",
                &[
                    "-6",
                    "address",
                    "add",
                    &format!("{HOST6}/126"),
                    "dev",
                    HOST_LINK,
                    "nodad",
                ],
                None,
            )?;
            self.runner.run(
                "ip",
                &[
                    "-n",
                    NAMESPACE,
                    "address",
                    "add",
                    &format!("{APP4}/30"),
                    "dev",
                    PEER_LINK,
                ],
                None,
            )?;
            self.runner.run(
                "ip",
                &[
                    "-n",
                    NAMESPACE,
                    "-6",
                    "address",
                    "add",
                    &format!("{APP6}/126"),
                    "dev",
                    PEER_LINK,
                    "nodad",
                ],
                None,
            )?;
            self.runner
                .run("ip", &["-n", NAMESPACE, "link", "set", "lo", "up"], None)?;
            self.runner.run(
                "ip",
                &[
                    "-n",
                    NAMESPACE,
                    "link",
                    "set",
                    PEER_LINK,
                    "mtu",
                    &request.mtu.to_string(),
                    "up",
                ],
                None,
            )?;
            self.runner.run(
                "ip",
                &["-n", NAMESPACE, "route", "add", "default", "via", HOST4],
                None,
            )?;
            self.runner.run(
                "ip",
                &[
                    "-n", NAMESPACE, "-6", "route", "add", "default", "via", HOST6,
                ],
                None,
            )?;
            self.runner.run(
                "sysctl",
                &[
                    "-q",
                    "-w",
                    &format!("net.ipv4.conf.{HOST_LINK}.forwarding=1"),
                    &format!("net.ipv4.conf.{HOST_LINK}.rp_filter=0"),
                    &format!("net.ipv6.conf.{HOST_LINK}.forwarding=1"),
                    &format!("net.ipv6.conf.{HOST_LINK}.keep_addr_on_down=1"),
                ],
                None,
            )?;
            self.apply_application_routing(request)?;
            anyhow::ensure!(
                self.application_configuration_exists(request),
                "application route verification failed"
            );
            Ok(())
        };
        if let Err(error) = action() {
            // Failed setup cannot leave a usable veth. Keep ownership metadata if
            // teardown fails so a later Disconnect can retry it safely.
            let _ = self.destroy_applications();
            return Err(error);
        }
        Ok(())
    }

    fn ensure_application_address_space(&self) -> Result<()> {
        for (family, cidr) in [
            ("-4", "169.254.83.0/30"),
            ("-6", "fd73:6972:696e:ffff::/126"),
        ] {
            let output = self
                .runner
                .output("ip", &[family, "-j", "address", "show"])?;
            let interfaces: Vec<serde_json::Value> = serde_json::from_slice(&output)?;
            let wanted: IpNet = cidr.parse()?;
            for info in interfaces
                .iter()
                .filter_map(|interface| interface["addr_info"].as_array())
                .flatten()
            {
                if let (Some(address), Some(prefix)) =
                    (info["local"].as_str(), info["prefixlen"].as_u64())
                {
                    let existing: IpNet = format!("{address}/{prefix}").parse()?;
                    anyhow::ensure!(
                        !wanted.contains(&existing.addr()) && !existing.contains(&wanted.addr()),
                        "application subnet overlaps an existing interface"
                    );
                }
            }
        }
        Ok(())
    }

    fn write_application_dns(&self, address: Ipv4Addr) -> Result<()> {
        ensure_owned_directory(&self.namespace_directory)?;
        let directory = self.namespace_directory.join(NAMESPACE);
        let marker = self.namespace_directory.join(".sirinvpn-apps-owner");
        if directory.exists() {
            validate_owned_directory(&directory)?;
            anyhow::ensure!(
                read_owned_file(&marker, 128)? == CONFIG_OWNER.as_bytes(),
                "namespace configuration is not owned"
            );
        } else {
            if marker.exists() {
                anyhow::ensure!(
                    read_owned_file(&marker, 128)? == CONFIG_OWNER.as_bytes(),
                    "namespace configuration is not owned"
                );
            }
            write_owned_file(&marker, CONFIG_OWNER.as_bytes(), 0o644)?;
            fs::create_dir(&directory)?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))?;
        }
        clean_dns_temporary_files(&directory)?;
        let original = fs::read_to_string("/etc/nsswitch.conf")?;
        let mut nss = original
            .lines()
            .filter(|line| {
                line.split(':')
                    .next()
                    .is_none_or(|key| key.trim() != "hosts")
            })
            .collect::<Vec<_>>()
            .join("\n");
        nss.push_str("\nhosts: files dns\n");
        write_owned_file(&directory.join("nsswitch.conf"), nss.as_bytes(), 0o644)?;
        write_owned_file(
            &directory.join("resolv.conf"),
            format!("nameserver {address}\noptions timeout:2 attempts:2\n").as_bytes(),
            0o644,
        )
    }

    fn remove_application_dns(&self) -> Result<()> {
        let directory = self.namespace_directory.join(NAMESPACE);
        let marker = self.namespace_directory.join(".sirinvpn-apps-owner");
        if !directory.exists() {
            if marker.exists() {
                anyhow::ensure!(
                    read_owned_file(&marker, 128)? == CONFIG_OWNER.as_bytes(),
                    "namespace configuration is not owned"
                );
                fs::remove_file(marker)?;
            }
            return Ok(());
        }
        validate_owned_directory(&directory)?;
        anyhow::ensure!(
            read_owned_file(&marker, 128)? == CONFIG_OWNER.as_bytes(),
            "namespace configuration is not owned"
        );
        clean_dns_temporary_files(&directory)?;
        for name in ["resolv.conf", "nsswitch.conf"] {
            remove_file_if_exists(&directory.join(name))?;
        }
        fs::remove_dir(directory)?;
        fs::remove_file(marker)?;
        Ok(())
    }
}

fn clean_dns_temporary_files(directory: &Path) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "resolv.conf" || name == "nsswitch.conf" {
            continue;
        }
        anyhow::ensure!(
            name.to_str()
                .is_some_and(|name| name.starts_with(".application-")),
            "unexpected namespace configuration"
        );
        read_owned_file(&entry.path(), 65536)?;
        fs::remove_file(entry.path())?;
    }
    Ok(())
}

fn validate_owned_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.uid() == nix::unistd::Uid::effective().as_raw()
            && metadata.mode() & 0o022 == 0,
        "untrusted application directory"
    );
    Ok(())
}

fn ensure_owned_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    validate_owned_directory(path)
}

fn read_owned_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == nix::unistd::Uid::effective().as_raw()
            && metadata.mode() & 0o022 == 0
            && metadata.len() <= maximum,
        "untrusted application state"
    );
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() as u64 <= maximum, "application state too large");
    Ok(bytes)
}

fn write_owned_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("missing application directory"))?;
    validate_owned_directory(parent)?;
    let mut file = tempfile::Builder::new()
        .prefix(".application-")
        .tempfile_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests;
