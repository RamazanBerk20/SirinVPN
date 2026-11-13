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

/// How the intent on disk relates to the durable document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Consistency {
    Absent,
    /// The transaction never replaced the document.
    Previous,
    /// The document was replaced; publication may still be pending.
    Next,
    /// Root maintenance (repair/`init`/restore) replaced the document after the intent.
    Stale,
}

fn read(paths: &ServerPaths) -> Result<Option<Intent>> {
    use std::io::Read;
    let file = match files::open_no_follow(&path(paths)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
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
    Ok(Some(intent))
}

/// Errors only for a malformed, oversized, foreign-owned or symlinked intent.
pub(crate) fn inspect(paths: &ServerPaths) -> Result<Consistency> {
    let Some(intent) = read(paths)? else {
        return Ok(Consistency::Absent);
    };
    let authority = fingerprint(&load_authorization(&paths.authorization)?)?;
    Ok(if authority == intent.previous {
        Consistency::Previous
    } else if authority == intent.next {
        Consistency::Next
    } else {
        Consistency::Stale
    })
}

pub(super) fn validate(paths: &ServerPaths) -> Result<()> {
    if inspect(paths)? == Consistency::Stale {
        bail!(
            "authorization recovery authority mismatch; run `sirinvpn-server authorization doctor`"
        );
    }
    Ok(())
}

/// Startup only, before the first recovery and with startup containment installed. A
/// stale intent means root maintenance wrote the durable document while the daemon was
/// stopped; that document is authoritative (see `Host::intent`). Recovery then enforces
/// exactly it under containment, so access it removed cannot survive. Malformed intents
/// still fail closed.
pub(crate) fn discard_stale(paths: &ServerPaths) -> Result<bool> {
    if inspect(paths)? != Consistency::Stale {
        return Ok(false);
    }
    remove(paths)?;
    Ok(true)
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
