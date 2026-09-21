use super::*;
use std::collections::BTreeMap;

impl LinuxNetworkHelper<SystemRunner> {
    pub fn launch_application(
        &self,
        launch: &ApplicationLaunchRequest,
    ) -> Result<ApplicationLaunchResult> {
        require_root()?;
        launch.validate()?;
        // pkexec supplies this value after authenticating the original caller.
        // Never accept a caller-selected UID in the JSON request.
        let uid: u32 = std::env::var("PKEXEC_UID")?.parse()?;
        anyhow::ensure!(
            uid != 0,
            "launch applications from your regular desktop account"
        );
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))?
            .ok_or_else(|| anyhow!("local application account is unavailable"))?;
        let executable = fs::canonicalize(&launch.executable)?;
        let metadata = fs::metadata(&executable)?;
        anyhow::ensure!(
            metadata.is_file() && metadata.mode() & 0o111 != 0,
            "choose an executable file"
        );
        reject_host_launchers(&executable)?;
        reject_running_instance(uid, &executable)?;
        application_command(launch, &executable, &user)?;
        let _lock = self.lock_operations()?;
        let state = self.read_state()?;
        anyhow::ensure!(
            state.server_id == launch.server_id
                && state.has_connected
                && !state.reconnecting
                && !state.waiting_for_user
                && state.observation_is_fresh()
                && state.routing.mode == TunnelRoutingMode::SelectedApplications,
            "connect this server in Selected applications mode before launching"
        );
        let desired = self.read_persistent()?;
        let request = current_persistent_request(&desired, Some(&state));
        anyhow::ensure!(
            self.tunnel_configuration_exists(&request)
                && established_handshake_is_healthy(
                    self.latest_handshake_timestamp(),
                    now_unix(),
                    None
                ),
            "the application tunnel is not ready"
        );
        self.prepare_application_network(&request, uid)?;
        let helper_binary = trusted_executable(&std::env::current_exe()?)?;
        let mut command = Command::new(system_program("ip")?);
        command
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C")
            .env("PKEXEC_UID", uid.to_string())
            .current_dir("/")
            .args(["netns", "exec", NAMESPACE])
            .arg(helper_binary)
            .arg("application-child")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn()?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("application handoff unavailable"))?
            .write_all(&serde_json::to_vec(launch)?)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        loop {
            if let Some(status) = child.try_wait()? {
                anyhow::ensure!(
                    status.success(),
                    "application launch failed; check the executable, the VPS DNS service and host forwarding rules"
                );
                return Ok(ApplicationLaunchResult {
                    process_id: None,
                    completed: true,
                });
            }
            if process_is_unprivileged_in_namespace(child.id(), uid) {
                return Ok(ApplicationLaunchResult {
                    process_id: Some(child.id()),
                    completed: false,
                });
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!("application isolation could not be confirmed");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Internal second stage, entered only after ip has created private network
    /// and mount namespaces. No user executable runs before the privilege drop.
    pub fn enter_application(&self, launch: &ApplicationLaunchRequest) -> Result<()> {
        use std::os::unix::process::CommandExt;
        require_root()?;
        launch.validate()?;
        let uid: u32 = std::env::var("PKEXEC_UID")?.parse()?;
        let network = self.read_application_network()?;
        anyhow::ensure!(
            uid != 0 && network.uid == uid && network.server_id == launch.server_id,
            "application session changed"
        );
        let named = fs::metadata(format!("/run/netns/{NAMESPACE}"))?;
        let current = fs::metadata("/proc/self/ns/net")?;
        anyhow::ensure!(
            named.ino() == current.ino() && named.dev() == current.dev(),
            "application namespace was not entered"
        );
        // An accept verdict in our table cannot override a host firewall's
        // forwarding drop. Verify the private DNS path before launching the app.
        std::net::TcpStream::connect_timeout(
            &SocketAddr::new(IpAddr::V4(network.dns_address), 53),
            Duration::from_secs(2),
        )
        .map_err(|_| anyhow!("application forwarding cannot reach private DNS"))?;
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))?
            .ok_or_else(|| anyhow!("application account unavailable"))?;
        let executable = fs::canonicalize(&launch.executable)?;
        reject_host_launchers(&executable)?;
        // Validate desktop paths before replacing the runtime view.
        application_command(launch, &executable, &user)?;
        let mut launch = launch.clone();
        runtime::isolate(&mut launch, &user)?;
        let error = application_command(&launch, &executable, &user)?.exec();
        Err(error.into())
    }
}

pub(super) fn system_program(name: &str) -> Result<PathBuf> {
    for directory in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        let candidate = Path::new(directory).join(name);
        if let Ok(canonical) = trusted_executable(&candidate) {
            return Ok(canonical);
        }
    }
    bail!("a required system application launcher is unavailable")
}

fn trusted_executable(path: &Path) -> Result<PathBuf> {
    let canonical = path.canonicalize()?;
    for ancestor in canonical.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        anyhow::ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "untrusted system launcher path"
        );
    }
    let metadata = fs::metadata(&canonical)?;
    anyhow::ensure!(
        metadata.is_file() && metadata.mode() & 0o111 != 0,
        "system launcher is not executable"
    );
    Ok(canonical)
}

fn application_command(
    launch: &ApplicationLaunchRequest,
    executable: &Path,
    user: &nix::unistd::User,
) -> Result<Command> {
    let uid = user.uid.as_raw();
    let mut environment = BTreeMap::from([
        (
            "HOME".to_owned(),
            user.dir
                .to_str()
                .ok_or_else(|| anyhow!("invalid home directory"))?
                .to_owned(),
        ),
        ("USER".into(), user.name.clone()),
        ("LOGNAME".into(), user.name.clone()),
        ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
        (
            "DBUS_SESSION_BUS_ADDRESS".into(),
            "unix:path=/run/sirinvpn/no-application-bus".into(),
        ),
        ("GTK_USE_PORTAL".into(), "0".into()),
        ("GIO_USE_VFS".into(), "local".into()),
        ("NO_AT_BRIDGE".into(), "1".into()),
    ]);
    for (key, value) in &launch.environment {
        if key == "XDG_RUNTIME_DIR" {
            let expected = format!("/run/user/{uid}");
            anyhow::ensure!(*value == expected, "invalid desktop runtime directory");
            let metadata = fs::symlink_metadata(value)?;
            anyhow::ensure!(
                metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o077 == 0,
                "untrusted desktop runtime directory"
            );
        }
        if key == "DISPLAY" {
            anyhow::ensure!(
                value.starts_with(':')
                    && value[1..].chars().all(|c| c.is_ascii_digit() || c == '.'),
                "only local graphical displays are supported"
            );
        }
        if key == "WAYLAND_DISPLAY" {
            anyhow::ensure!(
                !value.is_empty() && !value.contains('/') && value != "." && value != "..",
                "invalid Wayland display"
            );
        }
        environment.insert(key.clone(), value.clone());
    }
    // Root executes only fixed, root-owned system tools with a clean environment.
    // All user-controlled environment and executable arguments are applied AFTER
    // setpriv has removed every capability and permanently dropped root.
    let mut command = Command::new(system_program("setpriv")?);
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .current_dir("/")
        .args([
            "--reuid",
            &uid.to_string(),
            "--regid",
            &user.gid.as_raw().to_string(),
            "--init-groups",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
            "--",
        ])
        .arg(system_program("env")?)
        .args(["-i", "--chdir"])
        .arg(&user.dir)
        .arg("--")
        .args(
            environment
                .iter()
                .map(|(key, value)| format!("{key}={value}")),
        )
        .arg(executable)
        .args(&launch.arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(command)
}

fn reject_host_launchers(executable: &Path) -> Result<()> {
    let name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    anyhow::ensure!(
        !matches!(
            name,
            "flatpak"
                | "snap"
                | "systemd-run"
                | "gtk-launch"
                | "gio"
                | "xdg-open"
                | "pkexec"
                | "sudo"
                | "su"
                | "runuser"
        ),
        "choose the application's executable; portal, sandbox and desktop-service launchers are unsupported"
    );
    Ok(())
}

fn reject_running_instance(uid: u32, executable: &Path) -> Result<()> {
    let namespace = fs::metadata(format!("/run/netns/{NAMESPACE}")).ok();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if !entry
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        if !entry.metadata().is_ok_and(|metadata| metadata.uid() == uid) {
            continue;
        }
        if fs::read_link(entry.path().join("exe")).is_ok_and(|path| path == executable) {
            let existing = fs::metadata(entry.path().join("ns/net")).ok();
            anyhow::ensure!(
                namespace
                    .as_ref()
                    .zip(existing.as_ref())
                    .is_some_and(|(a, b)| a.ino() == b.ino() && a.dev() == b.dev()),
                "close running instances of this application before launching in VPN"
            );
        }
    }
    Ok(())
}

fn process_is_unprivileged_in_namespace(pid: u32, uid: u32) -> bool {
    let Ok(executable) = fs::read_link(format!("/proc/{pid}/exe")) else {
        return false;
    };
    if ["ip", "setpriv", "env", "sirinvpn-helper"]
        .into_iter()
        .any(|name| executable.file_name().is_some_and(|file| file == name))
    {
        return false; // Privilege drop alone does not prove the application exec completed.
    }
    let Ok(namespace) = fs::metadata(format!("/run/netns/{NAMESPACE}")) else {
        return false;
    };
    let Ok(process) = fs::metadata(format!("/proc/{pid}/ns/net")) else {
        return false;
    };
    if namespace.ino() != process.ino() || namespace.dev() != process.dev() {
        return false;
    }
    let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
        return false;
    };
    let value = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
    };
    value("Uid:").is_some_and(|values| {
        let ids = values.split_whitespace().collect::<Vec<_>>();
        ids.len() == 4 && ids.into_iter().all(|value| value.parse::<u32>() == Ok(uid))
    }) && value("NoNewPrivs:") == Some("1")
        && ["CapEff:", "CapPrm:", "CapInh:", "CapAmb:", "CapBnd:"]
            .into_iter()
            .all(|key| value(key) == Some("0000000000000000"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn untrusted_environment_is_only_present_after_privilege_drop() {
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let launch = ApplicationLaunchRequest {
            server_id: crate::tests::request().server_id,
            executable: "/usr/bin/true".into(),
            arguments: vec!["$(never executed); --root".into()],
            environment: BTreeMap::from([("LANG".into(), "tr_TR.UTF-8".into())]),
        };
        launch.validate().unwrap();
        let command = application_command(&launch, &launch.executable, &user).unwrap();
        let arguments = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let privilege_drop = arguments
            .iter()
            .position(|arg| arg == "--no-new-privs")
            .unwrap();
        let locale = arguments
            .iter()
            .position(|arg| arg == "LANG=tr_TR.UTF-8")
            .unwrap();
        assert!(privilege_drop < locale);
        assert!(arguments.contains(&"--bounding-set=-all".into()));
        assert_eq!(arguments.last().unwrap(), "$(never executed); --root");
        assert!(!command.get_envs().any(|(key, _)| key == "LANG"));
        let mut bad = launch;
        bad.environment
            .insert("LD_PRELOAD".into(), "/tmp/evil.so".into());
        assert!(bad.validate().is_err());
    }
}
