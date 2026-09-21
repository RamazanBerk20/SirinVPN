use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    io::{Read, Write},
    path::Path,
};
use thiserror::Error;
use zeroize::Zeroizing;

pub(crate) const ENVELOPE_SCHEMA_VERSION: u16 = 1;
const KDF_NAME: &str = "argon2id-v19";
const KDF_MEMORY_KIB: u32 = 65_536;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 1;
const CIPHER_NAME: &str = "xchacha20poly1305";
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 24;
const KEY_LENGTH: usize = 32;
const MAX_PASSWORD_BYTES: usize = 1024;
const MIN_EXPORT_PASSWORD_CHARACTERS: usize = 12;

#[derive(Debug, Error)]
pub(crate) enum EncryptedBackupError {
    #[error("the backup password must contain at least 12 characters")]
    WeakPassword,
    #[error("the backup password is invalid")]
    InvalidPassword,
    #[error("the backup destination already exists")]
    DestinationExists,
    #[error("the backup file is too large")]
    FileTooLarge,
    #[error("the backup format is invalid")]
    InvalidFormat,
    #[error("the backup format version is not supported")]
    IncompatibleVersion,
    #[error("the backup password is incorrect or the file was modified")]
    AuthenticationFailed,
    #[error("the backup file operation failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KdfDescriptor {
    pub(crate) name: String,
    pub(crate) memory_kib: u32,
    pub(crate) iterations: u32,
    pub(crate) parallelism: u32,
    pub(crate) salt: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CipherDescriptor {
    pub(crate) name: String,
    pub(crate) nonce: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupEnvelope {
    pub(crate) format: String,
    pub(crate) schema_version: u16,
    pub(crate) kdf: KdfDescriptor,
    pub(crate) cipher: CipherDescriptor,
    pub(crate) ciphertext: String,
}

#[derive(Serialize)]
struct AuthenticatedHeader<'a> {
    format: &'a str,
    schema_version: u16,
    kdf: &'a KdfDescriptor,
    cipher: &'a CipherDescriptor,
}

pub(crate) fn validate_export_password(password: &str) -> Result<(), EncryptedBackupError> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(EncryptedBackupError::InvalidPassword);
    }
    if password.chars().count() < MIN_EXPORT_PASSWORD_CHARACTERS {
        return Err(EncryptedBackupError::WeakPassword);
    }
    Ok(())
}

pub(crate) fn validate_import_password(password: &str) -> Result<(), EncryptedBackupError> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Err(EncryptedBackupError::InvalidPassword);
    }
    Ok(())
}

pub(crate) fn encrypt(
    format: &str,
    plaintext: &[u8],
    password: &str,
) -> Result<Vec<u8>, EncryptedBackupError> {
    let mut salt = [0_u8; SALT_LENGTH];
    let mut nonce = [0_u8; NONCE_LENGTH];
    let mut rng = OsRng;
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);
    let kdf = KdfDescriptor {
        name: KDF_NAME.to_owned(),
        memory_kib: KDF_MEMORY_KIB,
        iterations: KDF_ITERATIONS,
        parallelism: KDF_PARALLELISM,
        salt: STANDARD.encode(salt),
    };
    let cipher = CipherDescriptor {
        name: CIPHER_NAME.to_owned(),
        nonce: STANDARD.encode(nonce),
    };
    let header = AuthenticatedHeader {
        format,
        schema_version: ENVELOPE_SCHEMA_VERSION,
        kdf: &kdf,
        cipher: &cipher,
    };
    let authenticated_header =
        serde_json::to_vec(&header).map_err(|_| EncryptedBackupError::InvalidFormat)?;
    let key = derive_key(password, &salt)?;
    let cipher_instance = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| EncryptedBackupError::InvalidFormat)?;
    let nonce = XNonce::from(nonce);
    let ciphertext = cipher_instance
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &authenticated_header,
            },
        )
        .map_err(|_| EncryptedBackupError::InvalidFormat)?;
    let envelope = BackupEnvelope {
        format: format.to_owned(),
        schema_version: ENVELOPE_SCHEMA_VERSION,
        kdf,
        cipher,
        ciphertext: STANDARD.encode(ciphertext),
    };
    serde_json::to_vec_pretty(&envelope).map_err(|_| EncryptedBackupError::InvalidFormat)
}

pub(crate) fn decrypt(
    expected_format: &str,
    bytes: &[u8],
    password: &str,
) -> Result<Zeroizing<Vec<u8>>, EncryptedBackupError> {
    let envelope: BackupEnvelope =
        serde_json::from_slice(bytes).map_err(|_| EncryptedBackupError::InvalidFormat)?;
    if envelope.format != expected_format {
        return Err(EncryptedBackupError::InvalidFormat);
    }
    if envelope.schema_version != ENVELOPE_SCHEMA_VERSION {
        return Err(EncryptedBackupError::IncompatibleVersion);
    }
    if envelope.kdf.name != KDF_NAME
        || envelope.kdf.memory_kib != KDF_MEMORY_KIB
        || envelope.kdf.iterations != KDF_ITERATIONS
        || envelope.kdf.parallelism != KDF_PARALLELISM
        || envelope.cipher.name != CIPHER_NAME
    {
        return Err(EncryptedBackupError::IncompatibleVersion);
    }
    let salt = decode_fixed::<SALT_LENGTH>(&envelope.kdf.salt)?;
    let nonce = decode_fixed::<NONCE_LENGTH>(&envelope.cipher.nonce)?;
    let ciphertext = decode_canonical(&envelope.ciphertext)?;
    if ciphertext.len() < 16 {
        return Err(EncryptedBackupError::InvalidFormat);
    }
    let header = AuthenticatedHeader {
        format: &envelope.format,
        schema_version: envelope.schema_version,
        kdf: &envelope.kdf,
        cipher: &envelope.cipher,
    };
    let authenticated_header =
        serde_json::to_vec(&header).map_err(|_| EncryptedBackupError::InvalidFormat)?;
    let key = derive_key(password, &salt)?;
    let cipher_instance = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| EncryptedBackupError::InvalidFormat)?;
    let nonce = XNonce::from(nonce);
    Ok(Zeroizing::new(
        cipher_instance
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &authenticated_header,
                },
            )
            .map_err(|_| EncryptedBackupError::AuthenticationFailed)?,
    ))
}

pub(crate) fn read_file(
    source: &Path,
    max_file_bytes: usize,
) -> Result<Vec<u8>, EncryptedBackupError> {
    let file = fs::File::open(source)?;
    if !file.metadata()?.is_file() {
        return Err(EncryptedBackupError::InvalidFormat);
    }
    let mut bytes = Vec::new();
    file.take((max_file_bytes + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_file_bytes {
        return Err(EncryptedBackupError::FileTooLarge);
    }
    Ok(bytes)
}

pub(crate) fn write_file(
    destination: &Path,
    bytes: &[u8],
    temporary_prefix: &str,
) -> Result<(), EncryptedBackupError> {
    if destination.as_os_str().is_empty() {
        return Err(EncryptedBackupError::InvalidFormat);
    }
    match fs::symlink_metadata(destination) {
        Ok(_) => return Err(EncryptedBackupError::DestinationExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(temporary_prefix)
        .tempfile_in(parent)?;
    sirinvpn_platform::files::restrict_file(temporary.as_file())?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    let persisted =
        sirinvpn_platform::files::persist(temporary, destination, false).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                EncryptedBackupError::DestinationExists
            } else {
                EncryptedBackupError::Io(error)
            }
        })?;
    persisted.sync_all()?;
    sirinvpn_platform::files::sync_directory(parent)?;
    Ok(())
}

fn derive_key(
    password: &str,
    salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_LENGTH]>, EncryptedBackupError> {
    let params = Params::new(
        KDF_MEMORY_KIB,
        KDF_ITERATIONS,
        KDF_PARALLELISM,
        Some(KEY_LENGTH),
    )
    .map_err(|_| EncryptedBackupError::InvalidFormat)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; KEY_LENGTH]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| EncryptedBackupError::InvalidFormat)?;
    Ok(key)
}

fn decode_fixed<const LENGTH: usize>(value: &str) -> Result<[u8; LENGTH], EncryptedBackupError> {
    decode_canonical(value)?
        .try_into()
        .map_err(|_| EncryptedBackupError::InvalidFormat)
}

fn decode_canonical(value: &str) -> Result<Vec<u8>, EncryptedBackupError> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| EncryptedBackupError::InvalidFormat)?;
    if STANDARD.encode(&decoded) != value {
        return Err(EncryptedBackupError::InvalidFormat);
    }
    Ok(decoded)
}
