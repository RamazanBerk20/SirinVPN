//! An optional signed one-line summary, published beside a release manifest as
//! `sirinvpn-release-notes.json`. It stays outside the manifest, whose strict
//! schema every installed release enforces, so a release root with or without
//! notes remains valid for old and new clients. The notes name one exact
//! manifest (digest and sequence) and carry a signature by the key that signed
//! that manifest; anything else is rejected and shown as no notes at all.
use crate::{
    MAX_KEY_BYTES, ReleaseError, canonical_json, check_size, parse_manifest, verify_manifest,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{
    Signature, Signer, SigningKey, VerifyingKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RELEASE_NOTES_SCHEMA_VERSION: u16 = 1;
pub const MAX_RELEASE_NOTES_BYTES: u64 = 4 * 1024;
/// A sentence or two, shown as one plain-text paragraph.
pub const MAX_RELEASE_SUMMARY_CHARACTERS: usize = 280;

const NOTES_SIGNATURE_DOMAIN: &[u8] = b"SirinVPN release notes signature v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseNotes {
    pub schema_version: u16,
    pub release_sequence: u64,
    pub manifest_sha256: String,
    pub summary: String,
    pub signature: String,
}

pub fn sign_release_notes(
    manifest_bytes: &[u8],
    summary: &str,
    private_key_pem: &str,
) -> Result<Vec<u8>, ReleaseError> {
    let manifest = parse_manifest(manifest_bytes)?;
    if !valid_summary(summary) {
        return Err(ReleaseError::InvalidReleaseNotes);
    }
    if private_key_pem.is_empty() || private_key_pem.len() as u64 > MAX_KEY_BYTES {
        return Err(ReleaseError::KeySize);
    }
    let signing_key =
        SigningKey::from_pkcs8_pem(private_key_pem).map_err(|_| ReleaseError::InvalidPrivateKey)?;
    let mut notes = ReleaseNotes {
        schema_version: RELEASE_NOTES_SCHEMA_VERSION,
        release_sequence: manifest.release_sequence,
        manifest_sha256: hex::encode(Sha256::digest(manifest_bytes)),
        summary: summary.to_owned(),
        signature: String::new(),
    };
    notes.signature = STANDARD.encode(signing_key.sign(&notes_message(&notes)).to_bytes());
    let bytes = canonical_json(&notes)?;
    check_size(
        &bytes,
        MAX_RELEASE_NOTES_BYTES,
        ReleaseError::InvalidReleaseNotes,
    )?;
    Ok(bytes)
}

/// Returns the summary when the notes are canonical and bounded, name this
/// exact manifest, and are signed by the key that verifiably signed it.
pub fn verify_release_notes(
    notes_bytes: &[u8],
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    public_key_pem: &str,
) -> Result<String, ReleaseError> {
    let verified = verify_manifest(manifest_bytes, signature_bytes, public_key_pem)?;
    check_size(
        notes_bytes,
        MAX_RELEASE_NOTES_BYTES,
        ReleaseError::InvalidReleaseNotes,
    )?;
    let notes: ReleaseNotes =
        serde_json::from_slice(notes_bytes).map_err(|_| ReleaseError::InvalidReleaseNotes)?;
    if notes.schema_version != RELEASE_NOTES_SCHEMA_VERSION
        || !valid_summary(&notes.summary)
        || canonical_json(&notes)? != notes_bytes
    {
        return Err(ReleaseError::InvalidReleaseNotes);
    }
    if notes.manifest_sha256 != verified.manifest_sha256
        || notes.release_sequence != verified.manifest.release_sequence
    {
        return Err(ReleaseError::ReleaseNotesMismatch);
    }
    let signature = STANDARD
        .decode(&notes.signature)
        .ok()
        .filter(|bytes| STANDARD.encode(bytes) == notes.signature)
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or(ReleaseError::InvalidReleaseNotes)?;
    VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|_| ReleaseError::InvalidPublicKey)?
        .verify_strict(&notes_message(&notes), &signature)
        .map_err(|_| ReleaseError::ReleaseNotesMismatch)?;
    Ok(notes.summary)
}

/// One plain-text line: no control or invisible formatting characters, no
/// markup and no links. Reviews render it as text, never as HTML.
fn valid_summary(summary: &str) -> bool {
    !summary.is_empty()
        && summary.trim() == summary
        && summary.chars().count() <= MAX_RELEASE_SUMMARY_CHARACTERS
        && !summary.contains("://")
        && !summary.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '<' | '>'
                        | '\u{200b}'..='\u{200f}'
                        | '\u{2028}'..='\u{202e}'
                        | '\u{2060}'..='\u{206f}'
                        | '\u{feff}'
                )
        })
}

/// Every part before the summary has a fixed length, so the message is unambiguous.
fn notes_message(notes: &ReleaseNotes) -> Vec<u8> {
    let mut message = NOTES_SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(notes.manifest_sha256.as_bytes());
    message.extend_from_slice(&notes.release_sequence.to_be_bytes());
    message.extend_from_slice(notes.summary.as_bytes());
    message
}

#[cfg(test)]
mod tests;
