use super::*;

/// Saves the login key next to the app's settings so the Owner can reach the
/// VPS later, also outside SirinVPN. The file is readable only by this user.
pub fn save_login_key(
    configuration_directory: &Path,
    server: &PreparedServer,
) -> std::io::Result<PathBuf> {
    let directory = configuration_directory.join("ssh-keys");
    sirinvpn_platform::files::create_private_directory(&directory)?;
    let path = directory.join(&server.name);
    sirinvpn_platform::files::atomic_write(&path, server.login_private_key().as_bytes(), false)?;
    Ok(path)
}

pub(super) fn login_key_path(
    configuration_directory: &Path,
    name: &str,
) -> std::io::Result<PathBuf> {
    // The name comes back from the UI; accept only names `PreparedServer` generates.
    let generated = name
        .strip_prefix("sirinvpn-")
        .is_some_and(|suffix| suffix.len() == 8 && suffix.bytes().all(|b| b.is_ascii_hexdigit()));
    if !generated {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    Ok(configuration_directory.join("ssh-keys").join(name))
}

pub fn load_login_key(
    configuration_directory: &Path,
    name: &str,
) -> std::io::Result<Zeroizing<String>> {
    std::fs::read_to_string(login_key_path(configuration_directory, name)?).map(Zeroizing::new)
}

/// Removes the saved login key once its server is deleted.
pub fn forget_login_key(configuration_directory: &Path, name: &str) -> std::io::Result<()> {
    match std::fs::remove_file(login_key_path(configuration_directory, name)?) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

pub(super) fn random_key() -> SigningKey {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *seed);
    SigningKey::from_bytes(&seed)
}

pub(super) fn ssh_string(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

pub(super) fn public_key_blob(key: &SigningKey) -> Vec<u8> {
    let mut blob = Vec::new();
    ssh_string(&mut blob, b"ssh-ed25519");
    ssh_string(&mut blob, key.verifying_key().as_bytes());
    blob
}

pub(super) fn openssh_public_key(key: &SigningKey, comment: &str) -> String {
    format!(
        "ssh-ed25519 {} {comment}",
        STANDARD.encode(public_key_blob(key))
    )
}

/// SHA-256 of the public key blob, as the installer pins host keys.
pub(super) fn fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)))
}

/// The unencrypted "openssh-key-v1" format that sshd and libssh2 both read.
pub(super) fn openssh_private_key(key: &SigningKey, comment: &str) -> Zeroizing<String> {
    let public = key.verifying_key();
    // The check value only detects a wrong passphrase; a fixed one keeps the output stable.
    let check = &Sha256::digest(public.as_bytes())[..4];
    let mut private = Zeroizing::new(Vec::new());
    private.extend_from_slice(check);
    private.extend_from_slice(check);
    ssh_string(&mut private, b"ssh-ed25519");
    ssh_string(&mut private, public.as_bytes());
    let mut pair = Zeroizing::new(key.to_bytes().to_vec());
    pair.extend_from_slice(public.as_bytes());
    ssh_string(&mut private, &pair);
    ssh_string(&mut private, comment.as_bytes());
    for padding in 1..=(8 - private.len() % 8) % 8 {
        private.push(padding as u8);
    }
    let mut body = Zeroizing::new(b"openssh-key-v1\0".to_vec());
    ssh_string(&mut body, b"none");
    ssh_string(&mut body, b"none");
    ssh_string(&mut body, b"");
    body.extend_from_slice(&1u32.to_be_bytes());
    ssh_string(&mut body, &public_key_blob(key));
    ssh_string(&mut body, &private);
    let encoded = Zeroizing::new(STANDARD.encode(&*body));
    let mut pem = Zeroizing::new(String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
    for line in encoded.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    pem
}
