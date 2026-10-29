//! Untrusted-input entry points for `fuzz/`, compiled only under `--cfg fuzzing`.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// An invitation code. The first byte selects raw text, `data` as the decoded
/// payload of a long code, or `data` as the compressed payload of a QR code.
pub fn invitation(data: &[u8]) {
    let Some((&mode, data)) = data.split_first() else {
        return;
    };
    let code = match mode % 3 {
        0 => String::from_utf8_lossy(data).into_owned(),
        1 => format!("sirin1.{}", URL_SAFE_NO_PAD.encode(data)),
        _ => format!("sirq1.{}", URL_SAFE_NO_PAD.encode(data)),
    };
    let _ = crate::DecodedInvitation::decode(&code);
}

/// A device backup. An even first byte selects the encrypted envelope, up to the
/// Argon2id derivation that is too slow to fuzz through; odd, the decrypted payload.
pub fn backup(data: &[u8]) {
    let Some((&mode, data)) = data.split_first() else {
        return;
    };
    if mode % 2 == 0 {
        let _ = crate::encrypted_backup::open("sirinvpn-device-backup", data);
    } else {
        let _ = crate::backup::parse_payload(data);
    }
}
