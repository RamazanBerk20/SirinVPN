use super::*;
use std::{os::unix::fs::PermissionsExt, process::Command};

struct Kernel {
    directory: tempfile::TempDir,
}

impl Kernel {
    fn new(values: &[(&str, &str)]) -> Self {
        let kernel = Self {
            directory: tempfile::tempdir().unwrap(),
        };
        for (key, value) in values {
            kernel.set(key, value);
        }
        let bin = kernel.path("bin");
        fs::create_dir(&bin).unwrap();
        // Records each write and applies it to the fake /proc/sys.
        let sysctl = bin.join("sysctl");
        fs::write(
            &sysctl,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >>'{log}'\n[ \"$1 $2\" = '-q -w' ] || exit 2\nprintf '%s\\n' \"${{3#*=}}\" >'{proc}/'\"${{3%%=*}}\"\n",
                log = kernel.path("sysctl.log").display(),
                proc = kernel.path("proc").display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&sysctl, fs::Permissions::from_mode(0o755)).unwrap();
        let systemctl = bin.join("systemctl");
        fs::write(
            &systemctl,
            format!(
                "#!/bin/sh\n[ \"$*\" = 'is-active --quiet docker' ] && [ -f '{}' ]\n",
                kernel.path("docker-active").display()
            ),
        )
        .unwrap();
        fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(kernel.path("backup")).unwrap();
        fs::create_dir(kernel.path("sysctl.d")).unwrap();
        kernel
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn set(&self, key: &str, value: &str) {
        let path = self.path("proc").join(key);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, format!("{value}\n")).unwrap();
    }

    fn get(&self, key: &str) -> String {
        fs::read_to_string(self.path("proc").join(key))
            .unwrap()
            .trim()
            .to_owned()
    }

    fn run(&self, snippet: &str) {
        let script = snippet
            .replace(
                SYSCTL_CONFIGURATION,
                &format!("{}/*.conf", self.path("sysctl.d").display()),
            )
            .replace("/proc/sys/", &format!("{}/", self.path("proc").display()))
            .replace(
                ORIGINAL_SYSCTL_RECORD,
                self.path("record").to_str().unwrap(),
            )
            .replace(
                "/etc/sysctl.d/90-sirinvpn.conf",
                self.path("90-sirinvpn.conf").to_str().unwrap(),
            );
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("set -eu\numask 077\n{script}"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.path("bin").display()),
            )
            .env("BACKUP_DIR", self.path("backup"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn record(&self) -> Option<String> {
        fs::read_to_string(self.path("record")).ok()
    }

    fn writes(&self) -> String {
        fs::read_to_string(self.path("sysctl.log")).unwrap_or_default()
    }
}

const IP_FORWARD: &str = "net/ipv4/ip_forward";
const IPV6_FORWARD: &str = "net/ipv6/conf/all/forwarding";
const ETH0_RA: &str = "net/ipv6/conf/eth0/accept_ra";
const ENS6_RA: &str = "net/ipv6/conf/ens6/accept_ra";

#[test]
fn first_install_records_originals_once_and_uninstall_returns_to_them() {
    let kernel = Kernel::new(&[
        (IP_FORWARD, "0"),
        (IPV6_FORWARD, "0"),
        (ETH0_RA, "1"),
        (ENS6_RA, "0"),
    ]);
    kernel.run(&record_original_sysctl(Some("eth0")));
    let originals =
        "net/ipv4/ip_forward=0\nnet/ipv6/conf/all/forwarding=0\nnet/ipv6/conf/eth0/accept_ra=1\n";
    assert_eq!(kernel.record().as_deref(), Some(originals));
    assert_eq!(
        fs::metadata(kernel.path("record"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    // SirinVPN's own values must never replace a recorded original. A repair
    // that moves IPv6 to another interface records only that new key.
    fs::write(kernel.path("90-sirinvpn.conf"), "net.ipv4.ip_forward=1\n").unwrap();
    for (key, value) in [(IP_FORWARD, "1"), (IPV6_FORWARD, "1"), (ETH0_RA, "2")] {
        kernel.set(key, value);
    }
    kernel.run(&record_original_sysctl(Some("eth0")));
    kernel.run(&record_original_sysctl(None));
    assert_eq!(kernel.record().as_deref(), Some(originals));
    kernel.run(&record_original_sysctl(Some("ens6")));
    kernel.set(ENS6_RA, "2");
    let mut record = format!("{originals}net/ipv6/conf/ens6/accept_ra=0\n");
    assert_eq!(kernel.record().as_deref(), Some(record.as_str()));

    // Only well-formed forwarding entries for present keys are applied.
    record.push_str(
        "kernel/core_pattern=1\nnet/ipv6/conf/../../../kernel/x/accept_ra=1\nnet/ipv4/ip_forward=1;reboot\nnet/ipv6/conf/eth9/accept_ra=1\n",
    );
    fs::write(kernel.path("record"), record).unwrap();
    kernel.run(&snapshot_original_sysctl());
    kernel.run(&restore_original_sysctl());
    assert_eq!(
        kernel.writes(),
        "-q -w net/ipv4/ip_forward=0\n-q -w net/ipv6/conf/all/forwarding=0\n-q -w net/ipv6/conf/eth0/accept_ra=1\n-q -w net/ipv6/conf/ens6/accept_ra=0\n"
    );
    for (key, value) in [
        (IP_FORWARD, "0"),
        (IPV6_FORWARD, "0"),
        (ETH0_RA, "1"),
        (ENS6_RA, "0"),
    ] {
        assert_eq!(kernel.get(key), value, "{key}");
    }

    // A failed uninstall returns to the values that were active before it.
    kernel.run(ROLLBACK_SYSCTL);
    for (key, value) in [
        (IP_FORWARD, "1"),
        (IPV6_FORWARD, "1"),
        (ETH0_RA, "2"),
        (ENS6_RA, "2"),
    ] {
        assert_eq!(kernel.get(key), value, "{key}");
    }
}

#[test]
fn docker_or_other_forwarding_configuration_keeps_forwarding_unchanged() {
    for other_user in [
        "docker",
        "net.ipv4.ip_forward = 1",
        "-net/ipv6/conf/all/forwarding=1",
    ] {
        let kernel = Kernel::new(&[(IP_FORWARD, "0"), (IPV6_FORWARD, "0"), (ETH0_RA, "1")]);
        kernel.run(&record_original_sysctl(Some("eth0")));
        for (key, value) in [(IP_FORWARD, "1"), (IPV6_FORWARD, "1"), (ETH0_RA, "2")] {
            kernel.set(key, value);
        }
        if other_user == "docker" {
            fs::write(kernel.path("docker-active"), "").unwrap();
        } else {
            fs::write(
                kernel.path("sysctl.d").join("99-other.conf"),
                format!("# other forwarding user\n{other_user}\n"),
            )
            .unwrap();
        }
        kernel.run(&snapshot_original_sysctl());
        kernel.run(&restore_original_sysctl());
        assert_eq!(kernel.writes(), "", "{other_user}");
        assert_eq!(kernel.get(IP_FORWARD), "1");
        assert_eq!(kernel.get(ETH0_RA), "2");
    }
}

#[test]
fn installs_that_predate_the_record_keep_forwarding_unchanged() {
    let kernel = Kernel::new(&[(IP_FORWARD, "1"), (IPV6_FORWARD, "1")]);
    fs::write(kernel.path("90-sirinvpn.conf"), "net.ipv4.ip_forward=1\n").unwrap();
    kernel.run(&record_original_sysctl(None));
    assert_eq!(kernel.record(), None);
    kernel.run(&snapshot_original_sysctl());
    kernel.run(&restore_original_sysctl());
    kernel.run(ROLLBACK_SYSCTL);
    assert_eq!(kernel.writes(), "");
    assert_eq!(kernel.get(IP_FORWARD), "1");
}

#[test]
fn kernels_without_ipv6_record_and_restore_only_ipv4_forwarding() {
    let kernel = Kernel::new(&[(IP_FORWARD, "0")]);
    kernel.run(&record_original_sysctl(Some("eth0")));
    assert_eq!(kernel.record().as_deref(), Some("net/ipv4/ip_forward=0\n"));
    kernel.set(IP_FORWARD, "1");
    kernel.run(&snapshot_original_sysctl());
    kernel.run(&restore_original_sysctl());
    assert_eq!(kernel.writes(), "-q -w net/ipv4/ip_forward=0\n");
    assert_eq!(kernel.get(IP_FORWARD), "0");
}

#[test]
fn install_records_before_applying_and_uninstall_restores_before_removing_the_record() {
    let request = InstallRequest {
        server_id: ServerId::new(),
        server_name: "Test".into(),
        target: SshTarget {
            host: "203.0.113.4".into(),
            port: 22,
            username: "root".into(),
            authentication: SshAuthentication::Agent,
            sudo_password: None,
            expected_host_key_sha256: Some("SHA256:test".into()),
        },
        server_binary: PathBuf::from("/tmp/server").into(),
        identity: new_identity_for_server("Test").unwrap().public,
        identity_reference: "id".into(),
        transport: TransportSetup::default(),
        dns_upstream: DnsUpstream::Recursive,
        private_dns_records: Vec::new(),
        nat64_prefix: None,
        replace_existing_installation: false,
    };
    let discovery = ServerDiscovery {
        os_id: "debian".into(),
        os_version: "13".into(),
        architecture: "x86_64".into(),
        default_interface: "eth0".into(),
        ipv6_default_interface: Some("ens6".into()),
        ssh_server_port: 22,
        ssh_local_address: None,
        ipv4_available: true,
        ipv6_available: true,
        nftables_available: true,
        wireguard_available: true,
        unbound_installed: true,
        sirinvpn_installed: false,
    };
    let script = install_script(
        &request,
        &discovery,
        "/tmp/sirinvpn-server",
        "/tmp/owner.crt",
        "fixture",
        script_transaction("10.77.0.2", true, false),
    );
    let record = script.find(&record_original_sysctl(Some("ens6"))).unwrap();
    assert!(record < script.find("cat >/etc/sysctl.d/90-sirinvpn.conf").unwrap());
    assert!(
        record
            > script
                .find("install -d -o root -g sirinvpn -m 0750 /etc/sirinvpn")
                .unwrap()
    );

    let script = uninstall_script("uninstall");
    let snapshot = script.find(&snapshot_original_sysctl()).unwrap();
    let armed = script.find("tar -C / -cpf").unwrap();
    let network_down = script.rfind("/etc/sirinvpn/network.sh down").unwrap();
    let restore = script.find(&restore_original_sysctl()).unwrap();
    let removal = script.rfind("for path in $MANAGED_PATHS").unwrap();
    assert!(snapshot < armed);
    // After 90-sirinvpn.conf is removed, so only other configuration counts.
    assert!(network_down < removal && removal < restore);
    let rollback = script.find(ROLLBACK_SYSCTL).unwrap();
    assert!(rollback < script.find("\nROLLBACK\n").unwrap());
}
