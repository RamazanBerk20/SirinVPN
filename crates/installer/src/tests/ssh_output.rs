use super::*;

#[test]
fn remote_output_is_bounded_before_reading_an_unlimited_stream() {
    let error = read_bounded_output(std::io::repeat(b'x'), 64).unwrap_err();
    assert_eq!(
        error.to_string(),
        "remote command returned an oversized response"
    );
}

#[test]
fn remote_output_accepts_empty_exact_limit_and_non_utf8_binary_data() {
    assert!(read_bounded_output(&b""[..], 64).unwrap().is_empty());
    assert_eq!(
        &*read_bounded_output(&[0xff, 0x00][..], 2).unwrap(),
        &[0xff, 0x00]
    );
    assert!(read_bounded_output(&b"abc"[..], 2).is_err());
}

#[test]
fn every_resolved_address_is_tried_in_order() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_address = closed.local_addr().unwrap();
    drop(closed);
    let open = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addresses = [closed_address, open.local_addr().unwrap()];
    assert!(connect_any(&addresses, Duration::from_secs(2)).is_ok());
    assert!(connect_any(&addresses[..1], Duration::from_secs(2)).is_err());
    assert!(connect_any(&[], Duration::from_secs(2)).is_err());
}

/// Runs the wrapped privileged command with sudo replaced by nothing, as sudo
/// behaves under NOPASSWD or a cached timestamp: it never reads stdin.
fn run_as_passwordless_sudo(command: &str, target: &SshTarget, input: &[u8]) -> String {
    let wrapped = privileged_command(command);
    let without_sudo = wrapped.strip_prefix("sudo -S -p '' ").unwrap();
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(without_sudo)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&privileged_stdin(target, input))
        .unwrap();
    String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap()
}

#[test]
fn an_unrequested_sudo_password_never_reaches_the_root_command() {
    let target = SshTarget {
        host: "203.0.113.9".into(),
        port: 22,
        username: "admin".into(),
        authentication: SshAuthentication::Agent,
        sudo_password: Some(Zeroizing::new("correct horse".into())),
        expected_host_key_sha256: None,
    };
    assert_eq!(
        run_as_passwordless_sudo("cat; echo done", &target, b""),
        "done\n"
    );
    assert_eq!(
        run_as_passwordless_sudo("cat", &target, b"snapshot bytes"),
        "snapshot bytes"
    );
    let without_password = SshTarget {
        sudo_password: None,
        ..target
    };
    assert_eq!(
        run_as_passwordless_sudo("cat; echo done", &without_password, b""),
        "done\n"
    );
}

/// An unprivileged OpenSSH server on loopback, for tests of the SSH channel
/// handling itself. `None` when this machine has no sshd.
struct LocalSshd {
    directory: tempfile::TempDir,
    child: std::process::Child,
    port: u16,
}

impl LocalSshd {
    fn start() -> Option<Self> {
        let sshd = Path::new("/usr/bin/sshd");
        if !sshd.exists() {
            eprintln!("skipping: /usr/bin/sshd is not installed");
            return None;
        }
        let directory = tempfile::tempdir().unwrap();
        for key in ["host", "client"] {
            let status = std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(directory.path().join(key))
                .status()
                .unwrap();
            assert!(status.success());
        }
        fs::copy(
            directory.path().join("client.pub"),
            directory.path().join("authorized_keys"),
        )
        .unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let root = directory.path().display();
        fs::write(
            directory.path().join("sshd_config"),
            format!(
                "Port {port}\nListenAddress 127.0.0.1\nHostKey {root}/host\nAuthorizedKeysFile {root}/authorized_keys\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\nPidFile {root}/sshd.pid\n"
            ),
        )
        .unwrap();
        let child = std::process::Command::new(sshd)
            .arg("-D")
            .arg("-f")
            .arg(directory.path().join("sshd_config"))
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "sshd did not start"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        Some(Self {
            directory,
            child,
            port,
        })
    }

    fn target(&self) -> SshTarget {
        let user = std::process::Command::new("id")
            .arg("-un")
            .output()
            .unwrap();
        SshTarget {
            host: "127.0.0.1".into(),
            port: self.port,
            username: String::from_utf8(user.stdout).unwrap().trim().to_owned(),
            authentication: SshAuthentication::PrivateKey {
                path: self.directory.path().join("client"),
                passphrase: None,
            },
            sudo_password: None,
            expected_host_key_sha256: None,
        }
    }
}

impl Drop for LocalSshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn a_flood_of_remote_stderr_cannot_stall_a_command() {
    let Some(sshd) = LocalSshd::start() else {
        return;
    };
    let target = sshd.target();
    let session = connect_transport(&target).unwrap();
    authenticate(&session, &target).unwrap();
    // Far more than the shared channel window, written before stdout closes.
    session.set_timeout(10_000);
    let started = std::time::Instant::now();
    let output = run(&session, "sh -c 'head -c 8000000 /dev/zero >&2; echo done'").unwrap();
    assert_eq!(output, "done\n");
    assert!(started.elapsed() < Duration::from_secs(10));
}
