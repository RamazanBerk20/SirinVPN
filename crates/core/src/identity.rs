use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{SigningKey, VerifyingKey, pkcs8::DecodePrivateKey};
use rand::rngs::OsRng;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    PKCS_ED25519,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::{pem::parse_x509_pem, prelude::FromDer};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const ED25519_OID: &str = "1.3.101.112";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicIdentity {
    pub wireguard_public_key: String,
    pub management_certificate_pem: String,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretIdentity {
    pub wireguard_private_key: String,
    pub management_private_key_pem: String,
}

impl std::fmt::Debug for SecretIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretIdentity")
            .field("wireguard_private_key", &"[REDACTED]")
            .field("management_private_key_pem", &"[REDACTED]")
            .finish()
    }
}

impl SecretIdentity {
    pub fn public_identity(&self, management_certificate_pem: &str) -> Result<PublicIdentity> {
        let wireguard_public_key = wireguard_public_key_from_private(&self.wireguard_private_key)?;
        let signing_key = SigningKey::from_pkcs8_pem(&self.management_private_key_pem)
            .context("management private key is invalid")?;
        if signing_key.verifying_key() != extract_ed25519_public_key(management_certificate_pem)? {
            bail!("management private key does not match its certificate");
        }
        Ok(PublicIdentity {
            wireguard_public_key,
            management_certificate_pem: management_certificate_pem.to_owned(),
        })
    }
}

pub struct LocalIdentity {
    pub public: PublicIdentity,
    pub secret: SecretIdentity,
}

impl LocalIdentity {
    pub fn generate(common_name: &str) -> Result<Self> {
        let private = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private);

        let key_pair = KeyPair::generate_for(&PKCS_ED25519)
            .context("could not generate the local management key")?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, common_name);
        let mut params = CertificateParams::new(Vec::<String>::new())
            .context("could not prepare the local management certificate")?;
        params.distinguished_name = distinguished_name;
        params.is_ca = IsCa::NoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let certificate = params
            .self_signed(&key_pair)
            .context("could not self-sign the local management certificate")?;

        let private_bytes = Zeroizing::new(private.to_bytes());
        let management_private_key_pem = Zeroizing::new(key_pair.serialize_pem());

        Ok(Self {
            public: PublicIdentity {
                wireguard_public_key: STANDARD.encode(public.as_bytes()),
                management_certificate_pem: certificate.pem(),
            },
            secret: SecretIdentity {
                wireguard_private_key: STANDARD.encode(private_bytes.as_ref()),
                management_private_key_pem: management_private_key_pem.to_string(),
            },
        })
    }
}

pub fn wireguard_public_key_from_private(private_key: &str) -> Result<String> {
    let private_bytes = Zeroizing::new(
        STANDARD
            .decode(private_key)
            .context("WireGuard private key is not valid base64")?,
    );
    if STANDARD.encode(private_bytes.as_slice()) != private_key {
        bail!("WireGuard private key is not canonical base64");
    }
    let private: [u8; 32] = private_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("WireGuard private key must contain 32 bytes"))?;
    let private = StaticSecret::from(*Zeroizing::new(private));
    Ok(STANDARD.encode(PublicKey::from(&private).as_bytes()))
}

pub(crate) fn extract_ed25519_public_key(certificate_pem: &str) -> Result<VerifyingKey> {
    let (remaining, pem) = parse_x509_pem(certificate_pem.as_bytes())
        .map_err(|_| anyhow::anyhow!("management certificate is invalid"))?;
    if !remaining.iter().all(u8::is_ascii_whitespace) || pem.label != "CERTIFICATE" {
        bail!("exactly one management certificate is required");
    }
    let (remaining_der, certificate) =
        x509_parser::certificate::X509Certificate::from_der(&pem.contents)
            .map_err(|_| anyhow::anyhow!("management certificate is invalid"))?;
    if !remaining_der.is_empty() {
        bail!("management certificate contains trailing data");
    }
    let subject = certificate.public_key();
    if subject.algorithm.algorithm.to_id_string() != ED25519_OID {
        bail!("management certificate must use Ed25519");
    }
    let bytes: [u8; 32] = subject
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| anyhow::anyhow!("management certificate public key is invalid"))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| anyhow::anyhow!("management certificate public key is invalid"))
}

pub(crate) fn validate_secret_identity(
    secret: &SecretIdentity,
    management_certificate_pem: &str,
) -> Result<()> {
    secret
        .public_identity(management_certificate_pem)
        .map(|_| ())
}

pub fn management_identity_fingerprint(certificate_pem: &str) -> Result<String> {
    let public_key = extract_ed25519_public_key(certificate_pem)?;
    Ok(hex::encode(Sha256::digest(public_key.as_bytes())))
}

pub fn management_certificate_fingerprint(certificate_pem: &str) -> Result<String> {
    let (remaining, pem) = parse_x509_pem(certificate_pem.as_bytes())
        .map_err(|_| anyhow::anyhow!("management certificate is invalid"))?;
    if !remaining.iter().all(u8::is_ascii_whitespace) || pem.label != "CERTIFICATE" {
        bail!("exactly one management certificate is required");
    }
    Ok(hex::encode(Sha256::digest(&pem.contents)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_are_unique_and_do_not_mix_key_types() {
        let first = LocalIdentity::generate("first").unwrap();
        let second = LocalIdentity::generate("second").unwrap();
        assert_ne!(
            first.public.wireguard_public_key,
            second.public.wireguard_public_key
        );
        assert_ne!(
            first.public.management_certificate_pem,
            second.public.management_certificate_pem
        );
        assert_eq!(
            first
                .secret
                .public_identity(&first.public.management_certificate_pem)
                .unwrap(),
            first.public
        );
        assert!(
            first
                .secret
                .public_identity(&second.public.management_certificate_pem)
                .is_err()
        );
        assert!(!format!("{:?}", first.secret).contains("PRIVATE KEY"));
    }
}
