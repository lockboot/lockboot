// SPDX-License-Identifier: MIT OR Apache-2.0

//! TPM attestation parsing and verification

use ecdsa::signature::hazmat::PrehashVerifier;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::VerifyError;
use crate::x509::{extract_public_key, hash_public_key, parse_cert_chain_pem, validate_cert_chain};

/// Result of successful TPM attestation verification
///
/// This struct is only returned when verification succeeds.
/// Verification checks:
/// 1. EK public key from attestation matches EK certificate's public key
/// 2. AK signature over nonce is valid
/// 3. Certificate chain validates to root CA
#[derive(Debug, Serialize)]
pub struct TpmVerifyResult {
    /// The nonce that was signed (hex-encoded)
    pub nonce: String,
    /// SHA-256 hash of the root CA's public key (hex string)
    pub root_pubkey_hash: String,
}

/// Verify ECDSA-SHA256 signature over a message
pub fn verify_ecdsa_p256(
    message: &[u8],
    signature_der: &[u8],
    public_key: &[u8],
) -> Result<(), VerifyError> {
    use p256::ecdsa::{Signature, VerifyingKey};

    // Parse the public key (SEC1/SECG format: 0x04 || X || Y for uncompressed)
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| VerifyError::SignatureInvalid(format!("Invalid public key: {}", e)))?;

    // Parse the DER-encoded signature
    let signature = Signature::from_der(signature_der)
        .map_err(|e| VerifyError::SignatureInvalid(format!("Invalid signature DER: {}", e)))?;

    // TPM signs the SHA-256 hash of the message
    let digest = Sha256::digest(message);

    verifying_key
        .verify_prehash(&digest, &signature)
        .map_err(|e| VerifyError::SignatureInvalid(format!("Signature verification failed: {}", e)))
}

/// Verify TPM attestation
///
/// This verification approach works with TCG standard EKs (decrypt-only, cannot sign).
/// It verifies:
/// 1. The EK certificate chain validates to a root CA
/// 2. The EK public key from the attestation output matches the certificate's EK public key
/// 3. The AK's signature over the nonce is valid
///
/// # Arguments
/// * `nonce_hex` - The nonce/attest_data as hex string
/// * `signature_hex` - DER-encoded ECDSA signature as hex string (from AK)
/// * `ak_pubkey_x_hex` - AK public key X coordinate (hex)
/// * `ak_pubkey_y_hex` - AK public key Y coordinate (hex)
/// * `ek_pubkey_x_hex` - EK public key X coordinate from attestation output (hex)
/// * `ek_pubkey_y_hex` - EK public key Y coordinate from attestation output (hex)
/// * `ek_certs_pem` - EK certificate chain in PEM format
///
/// # Returns
/// Verification result with nonce and root public key hash.
/// Returns an error if signature, chain validation, or EK pubkey matching fails.
pub fn verify_tpm_attestation(
    nonce_hex: &str,
    signature_hex: &str,
    ak_pubkey_x_hex: &str,
    ak_pubkey_y_hex: &str,
    ek_pubkey_x_hex: &str,
    ek_pubkey_y_hex: &str,
    ek_certs_pem: &str,
) -> Result<TpmVerifyResult, VerifyError> {
    // Decode hex inputs
    let nonce = hex::decode(nonce_hex)?;
    let signature = hex::decode(signature_hex)?;
    let ak_x = hex::decode(ak_pubkey_x_hex)?;
    let ak_y = hex::decode(ak_pubkey_y_hex)?;
    let ek_x = hex::decode(ek_pubkey_x_hex)?;
    let ek_y = hex::decode(ek_pubkey_y_hex)?;

    // Construct AK public key in SEC1 uncompressed format: 0x04 || X || Y
    let mut ak_pubkey = vec![0x04];
    ak_pubkey.extend(&ak_x);
    ak_pubkey.extend(&ak_y);

    // Construct EK public key in SEC1 uncompressed format: 0x04 || X || Y
    let mut ek_pubkey = vec![0x04];
    ek_pubkey.extend(&ek_x);
    ek_pubkey.extend(&ek_y);

    // Parse the certificate chain
    let chain = parse_cert_chain_pem(ek_certs_pem)?;

    // Validate the certificate chain (fails on error)
    validate_cert_chain(&chain)?;

    // Extract EK public key from the leaf certificate
    let cert_ek_pubkey = extract_public_key(&chain[0])?;

    // Compare EK public key from attestation output with certificate's EK public key
    if ek_pubkey != cert_ek_pubkey {
        return Err(VerifyError::SignatureInvalid(
            "EK public key from attestation does not match certificate's EK public key".into()
        ));
    }

    // Verify the AK's signature over the nonce
    // Note: The AK signs SHA-256(nonce), not the raw nonce
    verify_ecdsa_p256(&nonce, &signature, &ak_pubkey)?;

    // Get the root certificate's public key hash
    let root_cert = chain.last().ok_or_else(|| {
        VerifyError::ChainValidation("Empty certificate chain".into())
    })?;
    let root_pubkey = extract_public_key(root_cert)?;
    let root_pubkey_hash = hash_public_key(&root_pubkey);

    Ok(TpmVerifyResult {
        nonce: nonce_hex.to_string(),
        root_pubkey_hash,
    })
}
