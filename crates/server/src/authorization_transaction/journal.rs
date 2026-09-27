use super::*;
use sirinvpn_platform::files;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema_version: u16,
    generation: u64,
    previous: String,
    next: String,
}
fn path(paths: &ServerPaths) -> PathBuf {
    paths.authorization.with_extension("recovery.json")
}

pub(super) fn write(
    paths: &ServerPaths,
    previous: &AuthorizationDocument,
    next: &AuthorizationDocument,
    generation: u64,
) -> Result<()> {
    let intent = Intent {
        schema_version: 1,
        generation,
        previous: fingerprint(previous)?,
        next: fingerprint(next)?,
    };
    files::atomic_write(&path(paths), &serde_json::to_vec(&intent)?, true)?;
    Ok(())
}

pub(super) fn validate(paths: &ServerPaths) -> Result<()> {
    use std::io::Read;
    let file = match files::open_no_follow(&path(paths)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    files::validate_private_file(&file)?;
    let mut bytes = Vec::new();
    file.take(1025).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 {
        bail!("authorization recovery intent is too large");
    }
    let intent: Intent = serde_json::from_slice(&bytes)?;
    if intent.schema_version != 1
        || intent.generation == 0
        || [&intent.previous, &intent.next]
            .iter()
            .any(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        bail!("invalid authorization recovery intent");
    }
    let authority = fingerprint(&load_authorization(&paths.authorization)?)?;
    if authority != intent.previous && authority != intent.next {
        bail!("authorization recovery authority mismatch");
    }
    Ok(())
}

pub(super) fn remove(paths: &ServerPaths) -> Result<()> {
    match fs::remove_file(path(paths)) {
        Ok(()) => files::sync_directory(
            paths
                .authorization
                .parent()
                .context("authorization directory missing")?,
        )?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
