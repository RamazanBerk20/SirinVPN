use super::*;
use sirinvpn_release::{MAX_RELEASE_NOTES_BYTES, sign_release_notes, verify_release_notes};

#[derive(Args)]
pub(super) struct NotesArguments {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    signature: PathBuf,
    /// UTF-8 plain-text file with a sentence or two; surrounding whitespace is ignored.
    #[arg(long)]
    summary: PathBuf,
    #[arg(long)]
    private_key: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Serialize)]
struct CreatedNotes {
    notes: String,
    summary: String,
}

/// Signs the optional `sirinvpn-release-notes.json` for an existing signed release.
pub(super) fn notes(arguments: NotesArguments, json: bool) -> Result<()> {
    let manifest = read_regular_bounded(&arguments.manifest, MAX_MANIFEST_BYTES, "manifest")?;
    let signature = read_regular_bounded(
        &arguments.signature,
        MAX_SIGNATURE_BYTES,
        "signature envelope",
    )?;
    let summary = read_regular_bounded(&arguments.summary, MAX_RELEASE_NOTES_BYTES, "summary")?;
    let summary = std::str::from_utf8(&summary)
        .map_err(|_| anyhow!("the release summary is not UTF-8 text"))?
        .trim();
    let private_key_bytes = Zeroizing::new(read_private_key(&arguments.private_key)?);
    let private_key = std::str::from_utf8(&private_key_bytes)
        .map_err(|_| anyhow!("the release private key is not UTF-8 PEM"))?;
    let notes = sign_release_notes(&manifest, summary, private_key)?;
    // Clients drop notes signed by any key other than the manifest's.
    let public_key = SigningPublicKey::from_private(private_key)?;
    verify_release_notes(&notes, &manifest, &signature, &public_key.pem)
        .context("sign the notes with the key that signed this manifest")?;
    write_new(&arguments.output, &notes, 0o644)?;
    let result = CreatedNotes {
        notes: arguments.output.display().to_string(),
        summary: summary.to_owned(),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Created signed release notes {}.", result.notes);
    }
    Ok(())
}
