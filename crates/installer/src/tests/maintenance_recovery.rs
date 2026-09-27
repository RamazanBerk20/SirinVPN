use super::*;
use std::{
    os::unix::fs::PermissionsExt,
    process::{Command, Output},
};

struct Fixture {
    directory: tempfile::TempDir,
    script: String,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        for path in [
            "bin",
            "run",
            "etc/sirinvpn/authorization",
            "etc/systemd/system",
            "usr/local/lib/sirinvpn",
            "var/lib/sirinvpn-maintenance/sirinvpn-install-fixture.backup",
        ] {
            fs::create_dir_all(root.join(path)).unwrap();
        }
        let fixture = Self {
            directory,
            script: rollback_script(),
        };
        fixture.write("etc/sirinvpn/server.json", "old configuration");
        fixture.write("etc/sirinvpn/authorization-required", "required");
        fixture.write(
            "etc/sirinvpn/authorization/authorization.json",
            "before repair",
        );
        fixture.write("usr/local/lib/sirinvpn/sirinvpn-server", "old executable");
        fixture.write(
            "var/lib/sirinvpn-maintenance/sirinvpn-install-fixture.backup/existing",
            "etc/sirinvpn\nusr/local/lib/sirinvpn/sirinvpn-server\n",
        );
        let snapshot = Command::new("tar")
            .arg("-C")
            .arg(fixture.directory.path())
            .arg("-cpf")
            .arg(fixture.backup().join("managed.tar"))
            .arg("-T")
            .arg(fixture.backup().join("existing"))
            .status()
            .unwrap();
        assert!(snapshot.success());
        for file in [
            "backup-ready",
            "active.sirinvpn-server",
            "enabled.sirinvpn-server",
        ] {
            fs::write(fixture.backup().join(file), "").unwrap();
        }
        fixture.write("etc/sirinvpn/server.json", "candidate configuration");
        fixture.write(
            "etc/sirinvpn/authorization/authorization.json",
            "revoked during health checks",
        );
        fixture.shim(
            "systemctl",
            r#"printf '%s\n' "$*" >>"$SIRINVPN_TEST_ROOT/service-calls"
case "$*" in
  cat\ *) exit 1 ;;
  'restart sirinvpn-server') [ ! -f "$SIRINVPN_TEST_ROOT/fail-restart" ] || exit 66 ;;
esac
exit 0"#,
        );
        for program in [
            "ip",
            "iptables",
            "ip6tables",
            "sysctl",
            "userdel",
            "groupdel",
        ] {
            fixture.shim(program, "exit 1");
        }
        // Enumeration succeeds with an empty ruleset; a specific table is absent.
        fixture.shim("nft", "[ \"$*\" = 'list tables' ]");
        fixture
    }
    fn backup(&self) -> PathBuf {
        self.directory
            .path()
            .join("var/lib/sirinvpn-maintenance/sirinvpn-install-fixture.backup")
    }
    fn write(&self, path: &str, data: &str) {
        fs::write(self.directory.path().join(path), data).unwrap();
    }
    fn read(&self, path: &str) -> String {
        fs::read_to_string(self.directory.path().join(path)).unwrap()
    }
    fn shim(&self, program: &str, body: &str) {
        let path = self.directory.path().join("bin").join(program);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn run(&self, script: &str, boot: bool) -> Output {
        let root = self.directory.path().to_str().unwrap();
        let mut script = script.to_owned();
        for path in ["/var/lib", "/usr/local/lib", "/etc", "/run"] {
            script = script.replace(path, &format!("{root}{path}"));
        }
        script = script
            .replace("tar -C / -xpf", &format!("tar -C '{root}' -xpf"))
            .replace("\"/$path\"", &format!("\"{root}/$path\""));
        Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .arg("recovery-test")
            .args(if boot { vec!["--before-start"] } else { vec![] })
            .env("PATH", format!("{root}/bin:/usr/bin:/bin"))
            .env("SIRINVPN_TEST_ROOT", root)
            .output()
            .unwrap()
    }
    fn assert_restored(&self, authorization: &str) {
        assert_eq!(self.read("etc/sirinvpn/server.json"), "old configuration");
        assert_eq!(
            self.read("etc/sirinvpn/authorization/authorization.json"),
            authorization
        );
        assert!(!self.backup().exists());
    }
}

#[test]
fn rollback_preserves_revocations_after_a_cut_in_the_middle_of_file_restoration() {
    let fixture = Fixture::new();
    let interrupted = fixture.script.replace(
        "tar -C / -xpf \"$BACKUP_DIR/managed.tar\"",
        "tar -C / -xpf \"$BACKUP_DIR/managed.tar\"\nexit 77",
    );
    assert_eq!(fixture.run(&interrupted, false).status.code(), Some(77));
    assert_eq!(
        fixture.read("etc/sirinvpn/authorization/authorization.json"),
        "before repair"
    );
    assert!(
        fixture
            .backup()
            .join("preserved-authorization.tar")
            .exists()
    );
    let recovered = fixture.run(&fixture.script, true);
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    fixture.assert_restored("revoked during health checks");
    let calls = fixture.read("service-calls");
    assert!(calls.contains("--no-block restart sirinvpn-server"));
    assert!(!calls.lines().any(|line| line == "restart sirinvpn-server"));
}

#[test]
fn retry_after_a_failed_service_restart_keeps_later_authorization_changes() {
    let fixture = Fixture::new();
    fixture.write("fail-restart", "");
    assert_eq!(fixture.run(&fixture.script, false).status.code(), Some(66));
    assert!(fixture.backup().join("restoration-complete").exists());
    fixture.write(
        "etc/sirinvpn/authorization/authorization.json",
        "another device revoked after recovery",
    );
    fs::remove_file(fixture.directory.path().join("fail-restart")).unwrap();
    let recovered = fixture.run(&fixture.script, false);
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    fixture.assert_restored("another device revoked after recovery");
}

#[test]
fn incomplete_snapshot_and_committed_cleanup_never_restore_old_files() {
    for committed in [false, true] {
        let fixture = Fixture::new();
        if committed {
            fs::write(fixture.backup().join("committed"), "").unwrap();
        } else {
            fs::remove_file(fixture.backup().join("backup-ready")).unwrap();
        }
        let result = fixture.run(&fixture.script, false);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            fixture.read("etc/sirinvpn/server.json"),
            "candidate configuration"
        );
        assert_eq!(
            fixture.read("etc/sirinvpn/authorization/authorization.json"),
            "revoked during health checks"
        );
        assert!(!fixture.backup().exists());
    }
}

#[test]
#[ignore = "requires systemd-analyze; reads unit definitions without starting services"]
fn generated_recovery_units_have_no_systemd_ordering_cycle() {
    let directory = tempfile::tempdir().unwrap();
    let service = "sirinvpn-install-rollback-fixture";
    let rendered = maintenance::arm("fixture", false)
        .replace("$ROLLBACK_SERVICE", service)
        .replace(
            "$ROLLBACK_SCRIPT",
            "/var/lib/sirinvpn-maintenance/fixture.sh",
        );
    let mut units = Vec::new();
    for suffix in [".service", "-boot.service", ".timer"] {
        let name = format!("{service}{suffix}");
        let marker = format!("cat >/etc/systemd/system/{name} <<EOF\n");
        let definition = rendered
            .split(&marker)
            .nth(1)
            .unwrap()
            .split("\nEOF\n")
            .next()
            .unwrap();
        let path = directory.path().join(name);
        fs::write(&path, definition).unwrap();
        units.push(path);
    }
    for name in [
        "sirinvpn-network",
        "sirinvpn-firewall",
        "sirinvpn-doh",
        "unbound",
        "sirinvpn-server",
    ] {
        let dependency = if name == "sirinvpn-network" {
            format!("Requires={service}-boot.service\nAfter={service}-boot.service\n")
        } else {
            "Requires=sirinvpn-network.service\nAfter=sirinvpn-network.service\n".to_owned()
        };
        let path = directory.path().join(format!("{name}.service"));
        fs::write(
            &path,
            format!("[Unit]\n{dependency}[Service]\nType=oneshot\nExecStart=/usr/bin/true\n"),
        )
        .unwrap();
        units.push(path);
    }
    let result = Command::new("systemd-analyze")
        .arg("verify")
        .args(units)
        .env(
            "SYSTEMD_UNIT_PATH",
            format!(
                "{}:/usr/lib/systemd/system:/lib/systemd/system",
                directory.path().display()
            ),
        )
        .env("SYSTEMD_LOG_LEVEL", "warning")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn rollback_script() -> String {
    let identity = LocalIdentity::generate("Maintenance fixture").unwrap();
    let profile: ServerProfile = serde_json::from_value(serde_json::json!({
        "schema_version":1, "id":ServerId::new(), "name":"Maintenance fixture",
        "endpoint":{"host":"203.0.113.4","wireguard_port":51820},
        "client_tunnel_address":"10.77.0.2", "server_tunnel_address":"10.77.0.1",
        "server_wireguard_public_key":identity.public.wireguard_public_key,
        "pinned_server_certificate_pem":identity.public.management_certificate_pem,
        "client_management_certificate_pem":identity.public.management_certificate_pem,
        "identity_reference":"fixture", "role":"owner"
    }))
    .unwrap();
    let request = InstallRequest {
        server_id: profile.id,
        server_name: profile.name.clone(),
        target: SshTarget {
            host: profile.endpoint.host.clone(),
            port: 22,
            username: "root".into(),
            authentication: SshAuthentication::Agent,
            sudo_password: None,
            expected_host_key_sha256: None,
        },
        server_binary: "/fixture/server".into(),
        identity: identity.public,
        identity_reference: "fixture".into(),
        transport: TransportSetup::default(),
        dns_upstream: DnsUpstream::Recursive,
        private_dns_records: Vec::new(),
        replace_existing_installation: false,
    };
    let discovery = ServerDiscovery {
        os_id: "debian".into(),
        os_version: "13".into(),
        architecture: "x86_64".into(),
        default_interface: "eth0".into(),
        ipv6_default_interface: None,
        ssh_server_port: 22,
        ipv4_available: true,
        ipv6_available: false,
        nftables_available: true,
        wireguard_available: true,
        unbound_installed: true,
        sirinvpn_installed: true,
    };
    let mut transaction = script_transaction("10.77.0.2", false, false);
    transaction.expected_profile = Some(&profile);
    let generated = install_script(
        &request,
        &discovery,
        "/fixture/server",
        "/fixture/owner",
        "fixture",
        transaction,
    );
    generated
        .split("cat >\"$ROLLBACK_SCRIPT.preparing\" <<'ROLLBACK'\n")
        .nth(1)
        .unwrap()
        .split("\nROLLBACK\n")
        .next()
        .unwrap()
        .to_owned()
}
