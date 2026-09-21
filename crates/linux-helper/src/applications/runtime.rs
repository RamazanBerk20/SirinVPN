//! Hide host DNS caches and D-Bus endpoints in the already-private mount namespace.
//! Preserve only display credentials, a Wayland socket and the local audio socket.
//! This is process routing, not a sandbox for malicious programs using arbitrary IPC.
use super::*;
use std::os::unix::fs::FileTypeExt;

struct CarriedFiles {
    directory: tempfile::TempDir,
    mounts: Vec<PathBuf>,
}
impl CarriedFiles {
    fn bind(&mut self, source: &Path) -> Result<PathBuf> {
        let path = self.directory.path().join(self.mounts.len().to_string());
        fs::File::create(&path)?;
        mount(&["--bind", path_string(source)?, path_string(&path)?])?;
        self.mounts.push(path.clone());
        Ok(path)
    }
}
impl Drop for CarriedFiles {
    fn drop(&mut self) {
        for path in self.mounts.iter().rev() {
            if let Ok(program) = launch::system_program("umount") {
                let _ = Command::new(program)
                    .arg(path)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }
}
fn path_string(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow!("invalid application runtime path"))
}
fn mount(arguments: &[&str]) -> Result<()> {
    let status = Command::new(launch::system_program("mount")?)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    anyhow::ensure!(status.success(), "application runtime isolation failed");
    Ok(())
}

pub(super) fn isolate(
    request: &mut ApplicationLaunchRequest,
    user: &nix::unistd::User,
) -> Result<()> {
    // Always create our own mount namespace even if invoked by another root
    // launcher. Never rely on the caller's mount namespace already being private.
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)?;
    mount(&["--make-rprivate", "/"])?;
    let runtime = PathBuf::from(format!("/run/user/{}", user.uid));
    let mut carried = CarriedFiles {
        directory: tempfile::Builder::new()
            .prefix(".sirinvpn-display-")
            .tempdir_in("/tmp")?,
        mounts: Vec::new(),
    };
    let mut destinations = Vec::new();
    if let Some(display) = request.environment.get("WAYLAND_DISPLAY") {
        let source = runtime.join(display);
        let metadata = fs::metadata(&source)?;
        anyhow::ensure!(
            metadata.file_type().is_socket() && metadata.uid() == user.uid.as_raw(),
            "Wayland socket is unavailable"
        );
        destinations.push((carried.bind(&source)?, runtime.join(display)));
    }
    if let Some(authority) = request.environment.get("XAUTHORITY") {
        let source = fs::canonicalize(authority)?;
        if source.starts_with("/run") {
            anyhow::ensure!(
                fs::metadata(&source)?.is_file(),
                "invalid display authority"
            );
            let destination = runtime.join("sirinvpn-xauthority");
            destinations.push((carried.bind(&source)?, destination.clone()));
            request
                .environment
                .insert("XAUTHORITY".into(), path_string(&destination)?.to_owned());
        }
    }
    let audio = runtime.join("pulse/native");
    if fs::metadata(&audio).is_ok_and(|metadata| {
        metadata.file_type().is_socket() && metadata.uid() == user.uid.as_raw()
    }) {
        destinations.push((carried.bind(&audio)?, audio));
    }
    // ip netns exec may have bound these through /etc symlinks into /run. Restore
    // those private DNS files at their target after masking /run; never restore
    // any socket or host resolver state from the old runtime directory.
    let mut configuration = Vec::new();
    for name in ["/etc/resolv.conf", "/etc/nsswitch.conf"] {
        let target = fs::canonicalize(name)?;
        if target.starts_with("/run") {
            let bytes = read_owned_file(Path::new(name), 65536).or_else(|_| {
                // The conventional /etc path may be a symlink; its canonical
                // target is the private, root-owned namespace bind mount.
                read_owned_file(&target, 65536)
            })?;
            configuration.push((target, bytes));
        }
    }
    mount(&[
        "-t",
        "tmpfs",
        "-o",
        "mode=0755,nosuid,nodev,noexec,size=16m",
        "tmpfs",
        "/run",
    ])?;
    fs::create_dir_all(&runtime)?;
    nix::unistd::chown(&runtime, Some(user.uid), Some(user.gid))?;
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))?;
    for (path, bytes) in configuration {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("missing private DNS directory"))?;
        fs::create_dir_all(parent)?;
        write_owned_file(&path, &bytes, 0o644)?;
    }
    for (source, destination) in destinations {
        fs::create_dir_all(
            destination
                .parent()
                .ok_or_else(|| anyhow!("missing display directory"))?,
        )?;
        fs::File::create(&destination)?;
        mount(&["--bind", path_string(&source)?, path_string(&destination)?])?;
    }
    // Always provide the private runtime directory, including CLI launches.
    request
        .environment
        .insert("XDG_RUNTIME_DIR".into(), path_string(&runtime)?.to_owned());
    Ok(())
}
