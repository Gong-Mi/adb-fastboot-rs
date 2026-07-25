//! X.509 certificate generation from RSA 2048 private keys,
//! mirroring AOSP `vendor/adb/crypto/x509_generator.cpp`.

use rcgen::{
    BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose,
};
use thiserror::Error;

/// Errors that can occur during X.509 certificate generation.
#[derive(Error, Debug)]
pub enum CertError {
    /// Error from `rcgen` during certificate generation.
    #[error("rcgen error: {0}")]
    Rcgen(#[from] rcgen::Error),

    /// The provided RSA private key PEM could not be parsed.
    #[error("invalid private key PEM: {0}")]
    InvalidPrivateKey(String),
}

/// Generate a self-signed X.509 certificate from an RSA 2048 private key PEM.
///
/// # Parameters
/// - `rsa_private_key_pem`: an RSA private key in PEM format (PKCS#8 or PKCS#1).
///   You can obtain one via [`crate::crypto::key::export_private_key_to_pem`].
///
/// # Returns
/// `(certificate_der, private_key_der)` — both in DER format.
///
/// # Errors
/// Returns [`CertError::InvalidPrivateKey`] if the PEM cannot be parsed,
/// or [`CertError::Rcgen`] if certificate generation fails.
pub fn generate_self_signed_cert(
    rsa_private_key_pem: &str,
) -> Result<(Vec<u8>, Vec<u8>), CertError> {
    let key_pair = KeyPair::from_pem(rsa_private_key_pem)
        .map_err(|e| CertError::InvalidPrivateKey(e.to_string()))?;

    let mut params = CertificateParams::new(vec!["adb".to_string()])?;

    // Match AOSP's x509_generator.cpp: CA:TRUE, keyCertSign, 10-year validity
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CountryName, "US");
    params.distinguished_name.push(rcgen::DnType::OrganizationName, "Android");
    params.distinguished_name.push(rcgen::DnType::CommonName, "Adb");

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    // AOSP does NOT set extendedKeyUsage for ADB TLS certs
    params.extended_key_usages = vec![];
    let cert = params.self_signed(&key_pair)?;

    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();

    Ok((cert_der, key_der))
}
