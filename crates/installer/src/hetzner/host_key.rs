use super::*;

/// Step one of the host-key replacement, repeatable: creates the replacement
/// key once (a retry reuses it) and prints its public half. The server keeps
/// presenting the pinned key, so a lost reply changes nothing.
pub(super) const PREPARE_HOST_KEY: &str = "set -eu
key=/etc/ssh/ssh_host_ed25519_key
if ! ssh-keygen -y -f \"$key.new\" >/dev/null 2>&1; then
  rm -f \"$key.new\" \"$key.new.pub\"
  ssh-keygen -q -t ed25519 -N '' -C '' -f \"$key.new\"
fi
ssh-keygen -y -f \"$key.new\" | cut -d' ' -f1-2";

/// Step two, also repeatable: switches to the replacement whose public key the
/// client already holds. A configuration sshd rejects is put back, and a retry
/// after a lost reply only confirms the switch. At every point the server
/// presents either the pinned key or the one the client was told about.
pub(super) fn activate_host_key(public_key: &str) -> String {
    format!(
        "set -eu
key=/etc/ssh/ssh_host_ed25519_key
expected={expected}
public() {{ ssh-keygen -y -f \"$1\" | cut -d' ' -f1-2; }}
if [ -f \"$key.new\" ]; then
  [ \"$(public \"$key.new\")\" = \"$expected\" ]
  cp -p \"$key\" \"$key.previous\"
  mv -f \"$key.new\" \"$key\"
  if ! /usr/sbin/sshd -t; then
    mv -f \"$key\" \"$key.new\"
    mv -f \"$key.previous\" \"$key\"
    exit 1
  fi
fi
[ \"$(public \"$key\")\" = \"$expected\" ]
printf '%s\\n' \"$expected\" >\"$key.pub.tmp\"
mv -f \"$key.pub.tmp\" \"$key.pub\"
rm -f \"$key.previous\" \"$key.new.pub\"
systemctl reload ssh",
        expected = crate::shell_quote(public_key)
    )
}

pub(super) fn public_key_fingerprint(public_key: &str) -> Option<String> {
    public_key
        .trim()
        .strip_prefix("ssh-ed25519 ")
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|key| STANDARD.decode(key).ok())
        .filter(|blob| blob.starts_with(b"\0\0\0\x0bssh-ed25519"))
        .map(|blob| fingerprint(&blob))
}

/// Replaces the pre-seeded host key with one generated on the server and
/// returns its fingerprint. The replacement is learned over the session pinned
/// to the old key before it is activated, so a dropped connection never leaves
/// a key nobody knows: the server presents either the old pin or the returned one.
pub fn replace_host_key(target: &SshTarget) -> Result<String, InstallerError> {
    replace_host_key_with(target, |_| Ok(()))
}

/// As `replace_host_key`; `on_replacement` learns the replacement fingerprint
/// before it is activated (to persist it) and can stop the activation.
pub fn replace_host_key_with(
    target: &SshTarget,
    on_replacement: impl FnOnce(&str) -> Result<(), InstallerError>,
) -> Result<String, InstallerError> {
    let failure = |message: String| crate::phase_error("host key", anyhow::anyhow!(message));
    let pinned = || -> Result<ssh2::Session, InstallerError> {
        let session = crate::connect_transport(target)
            .map_err(|error| crate::phase_error("connection", error))?;
        crate::verify_host_key(&session, target.expected_host_key_sha256.as_deref())?;
        crate::authenticate(&session, target)?;
        Ok(session)
    };
    let session = pinned()?;
    let public = crate::run(&session, PREPARE_HOST_KEY)
        .map_err(|error| crate::phase_error("host key", error))?;
    let public = public.trim().to_owned();
    let replacement =
        public_key_fingerprint(&public).ok_or_else(|| failure("unexpected host key".into()))?;
    on_replacement(&replacement)?;
    let activate = activate_host_key(&public);
    let mut session = Some(session);
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(2));
        }
        if let Some(session) = &session
            && crate::run(session, &activate).is_ok()
        {
            return Ok(replacement);
        }
        // The reply may be lost after the switch: ask which key the server presents.
        let presented = Provisioner::host_key_fingerprint(&SshTarget {
            expected_host_key_sha256: None,
            ..target.clone()
        });
        match presented {
            Ok(presented) if presented == replacement => return Ok(replacement),
            Ok(presented)
                if Some(presented.as_str()) != target.expected_host_key_sha256.as_deref() =>
            {
                return Err(InstallerError::HostKeyMismatch);
            }
            _ => session = pinned().ok(),
        }
    }
    Err(failure(format!(
        "the server still presents the pre-seeded host key; the replacement {replacement} was not activated"
    )))
}

pub(super) fn presented_host_key(ipv4: Ipv4Addr) -> Option<String> {
    Provisioner::host_key_fingerprint(&SshTarget {
        host: ipv4.to_string(),
        port: 22,
        username: "unused".to_owned(),
        authentication: SshAuthentication::Agent,
        sudo_password: None,
        expected_host_key_sha256: None,
    })
    .ok()
}
