//! Disposable-VM check for Hetzner creation (tests/vm/hetzner-cloud-init.sh).
//! `prepare DIR` writes the cloud-init user data that `create_server` sends;
//! `verify DIR PORT` logs in to the booted guest with the pinned host key, then
//! replaces that key as `wait_until_ready` does and writes the new pin to
//! `DIR/replaced-host-key-sha256`.

use anyhow::{Context, Result, bail, ensure};
use sirinvpn_installer::{
    InstallerError, Provisioner,
    hetzner::{PreparedServer, replace_host_key, save_login_key, ssh_target},
};
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

fn main() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["prepare", directory] => {
            let directory = Path::new(directory);
            let server = PreparedServer::generate();
            save_login_key(directory, &server)?;
            fs::write(directory.join("user-data"), server.user_data())?;
            fs::write(directory.join("name"), &server.name)?;
            fs::write(directory.join("host-key-sha256"), server.host_key_sha256())?;
            println!("{}", server.host_key_sha256());
            Ok(())
        }
        ["verify", directory, port] => {
            let directory = Path::new(directory);
            let name = fs::read_to_string(directory.join("name"))?;
            let pin = fs::read_to_string(directory.join("host-key-sha256"))?;
            let key = Zeroizing::new(fs::read_to_string(
                directory.join("ssh-keys").join(name.trim()),
            )?);
            let mut target = ssh_target("127.0.0.1".parse()?, key, pin.trim().to_owned());
            target.port = port.parse().context("port")?;
            log_in(&target, 300)?;
            let mut other = target.clone();
            other.expected_host_key_sha256 =
                Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned());
            ensure!(
                matches!(
                    Provisioner::verify_ssh_login(&other),
                    Err(InstallerError::HostKeyMismatch)
                ),
                "a different pin was not rejected"
            );
            println!(
                "root login with the pre-seeded host key {} verified",
                pin.trim()
            );

            let replaced = replace_host_key(&target)?;
            ensure!(replaced != pin.trim(), "the host key was not replaced");
            let old = target.clone();
            target.expected_host_key_sha256 = Some(replaced.clone());
            log_in(&target, 30)?;
            ensure!(
                matches!(
                    Provisioner::verify_ssh_login(&old),
                    Err(InstallerError::HostKeyMismatch)
                ),
                "the pre-seeded host key is still offered"
            );
            fs::write(directory.join("replaced-host-key-sha256"), &replaced)?;
            println!("host key replaced by {replaced}; the pre-seeded key is no longer offered");
            Ok(())
        }
        _ => bail!("usage: hetzner_cloud_init prepare DIR | verify DIR PORT"),
    }
}

/// Retries while the guest boots or sshd restarts.
fn log_in(target: &sirinvpn_installer::SshTarget, seconds: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        match Provisioner::verify_ssh_login(target) {
            Ok(()) => return Ok(()),
            Err(error) if Instant::now() > deadline => bail!("guest not ready: {error}"),
            Err(_) => std::thread::sleep(Duration::from_secs(3)),
        }
    }
}
