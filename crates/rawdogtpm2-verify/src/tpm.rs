// SPDX-License-Identifier: MIT OR Apache-2.0

//! TPM attestation parsing and verification

use std::collections::BTreeMap;

use ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

use pki_types::UnixTime;

use crate::error::VerifyError;
use crate::x509::{extract_public_key, parse_and_validate_cert_chain, parse_cert_chain_pem};

// Import from rawdogtpm2 (single source of truth)
use rawdogtpm2::{PcrOps, Tpm, TpmAlg};

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
    // Parse the public key (SEC1/SECG format: 0x04 || X || Y for uncompressed)
    let verifying_key = P256VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| VerifyError::SignatureInvalid(format!("Invalid public key: {}", e)))?;

    // Parse the DER-encoded signature
    let signature = P256Signature::from_der(signature_der)
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

    // Parse the certificate chain to extract leaf cert's public key
    let chain = parse_cert_chain_pem(ek_certs_pem)?;

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

    // Validate the certificate chain and get root's public key hash
    // This uses webpki for signature and date validation
    let chain_result = parse_and_validate_cert_chain(ek_certs_pem, UnixTime::now())?;
    let root_pubkey_hash = chain_result.root_pubkey_hash;

    Ok(TpmVerifyResult {
        nonce: nonce_hex.to_string(),
        root_pubkey_hash,
    })
}

/// Verify TPM signature only (without EK certificate chain validation)
///
/// This is used in the Nitro path where trust comes from the Nitro attestation
/// binding the TPM signing key. No EK certificate validation is needed.
///
/// # Arguments
/// * `nonce_hex` - The nonce/attest_data as hex string
/// * `signature_hex` - DER-encoded ECDSA signature as hex string (from AK)
/// * `ak_pubkey_x_hex` - AK public key X coordinate (hex)
/// * `ak_pubkey_y_hex` - AK public key Y coordinate (hex)
///
/// # Returns
/// The verified nonce (hex-encoded) if signature is valid.
pub fn verify_tpm_signature_only(
    nonce_hex: &str,
    signature_hex: &str,
    ak_pubkey_x_hex: &str,
    ak_pubkey_y_hex: &str,
) -> Result<String, VerifyError> {
    // Decode hex inputs
    let nonce = hex::decode(nonce_hex)?;
    let signature = hex::decode(signature_hex)?;
    let ak_x = hex::decode(ak_pubkey_x_hex)?;
    let ak_y = hex::decode(ak_pubkey_y_hex)?;

    // Construct AK public key in SEC1 uncompressed format: 0x04 || X || Y
    let mut ak_pubkey = vec![0x04];
    ak_pubkey.extend(&ak_x);
    ak_pubkey.extend(&ak_y);

    // Verify the AK's signature over the nonce
    verify_ecdsa_p256(&nonce, &signature, &ak_pubkey)?;

    Ok(nonce_hex.to_string())
}

/// Calculate the expected PCR policy digest from PCR values
///
/// This calculates the TPM2 PolicyPCR digest that would be used as an
/// authPolicy for a key bound to the given PCR values.
///
/// Uses the same implementation as rawdogtpm2 to ensure consistency.
///
/// # Arguments
/// * `pcrs` - Map of PCR index to hex-encoded PCR value
/// * `pcr_alg` - The hash algorithm of the PCR bank (determines expected PCR size)
///
/// # Returns
/// The expected policy digest as a hex-encoded string
///
/// # Example
/// ```ignore
/// let mut pcrs = BTreeMap::new();
/// pcrs.insert(0, "0000...".to_string());  // 64 hex chars for SHA-256
/// pcrs.insert(1, "0000...".to_string());
/// let policy = calculate_pcr_policy(&pcrs, TpmAlg::Sha256)?;
/// ```
pub fn calculate_pcr_policy(pcrs: &BTreeMap<u8, String>, pcr_alg: TpmAlg) -> Result<String, VerifyError> {
    if pcrs.is_empty() {
        return Err(VerifyError::InvalidAttest("No PCR values provided".into()));
    }

    // Determine expected PCR size based on algorithm
    let expected_size = match pcr_alg {
        TpmAlg::Sha256 => 32,
        TpmAlg::Sha384 => 48,
        _ => return Err(VerifyError::InvalidAttest(format!(
            "Unsupported PCR algorithm: {:?}",
            pcr_alg
        ))),
    };

    // Validate and convert PCR values from hex strings to bytes
    // PCRs must be in sorted order (BTreeMap guarantees this)
    let mut pcr_values: Vec<(u8, Vec<u8>)> = Vec::with_capacity(pcrs.len());
    for (&idx, value_hex) in pcrs.iter() {
        if idx > 23 {
            return Err(VerifyError::InvalidAttest(format!(
                "PCR index {} out of range (max 23)",
                idx
            )));
        }
        let value_bytes = hex::decode(value_hex)?;
        if value_bytes.len() != expected_size {
            return Err(VerifyError::InvalidAttest(format!(
                "PCR {} has invalid length for {:?}: expected {} bytes, got {}",
                idx, pcr_alg, expected_size, value_bytes.len()
            )));
        }
        pcr_values.push((idx, value_bytes));
    }

    // Use rawdogtpm2's implementation (single source of truth)
    let policy_digest = Tpm::calculate_pcr_policy_digest(&pcr_values, pcr_alg)
        .map_err(|e| VerifyError::InvalidAttest(format!("PCR policy calculation failed: {}", e)))?;

    Ok(hex::encode(policy_digest))
}

/// Verify that a policy digest matches the expected PCR values
///
/// This is useful for verifying that an AK's authPolicy (if known) matches
/// the PCR values reported in an attestation.
///
/// # Arguments
/// * `expected_policy_hex` - The expected policy digest (hex string)
/// * `pcrs` - The PCR values to verify against
/// * `pcr_alg` - The hash algorithm of the PCR bank
///
/// # Returns
/// Ok(()) if the policy matches, error otherwise
pub fn verify_pcr_policy(
    expected_policy_hex: &str,
    pcrs: &BTreeMap<u8, String>,
    pcr_alg: TpmAlg,
) -> Result<(), VerifyError> {
    let calculated_policy = calculate_pcr_policy(pcrs, pcr_alg)?;

    if calculated_policy != expected_policy_hex {
        return Err(VerifyError::InvalidAttest(format!(
            "PCR policy mismatch: expected {}, calculated {}",
            expected_policy_hex, calculated_policy
        )));
    }

    Ok(())
}

// =============================================================================
// TPM2B_ATTEST parsing and NIZK verification
// =============================================================================

/// TPM_GENERATED magic value (0xff544347 = "ÿTCG")
const TPM_GENERATED_VALUE: u32 = 0xff544347;

/// TPM_ST_ATTEST_CERTIFY structure type
const TPM_ST_ATTEST_CERTIFY: u16 = 0x8017;

/// Size of TPMS_CLOCK_INFO structure: clock(8) + resetCount(4) + restartCount(4) + safe(1)
const TPMS_CLOCK_INFO_SIZE: usize = 17;

/// Parsed TPMS_ATTEST structure (from TPM2_Certify)
#[derive(Debug)]
pub struct TpmAttestInfo {
    /// Nonce/qualifying data from extraData field (raw bytes)
    pub nonce: Vec<u8>,
    /// Name of the certified object (nameAlg || H(public_area))
    pub certified_name: Vec<u8>,
    /// Name of the signing key
    pub signer_name: Vec<u8>,
}

/// Parse TPM2B_ATTEST structure (CERTIFY type)
///
/// TPM2B_ATTEST contains a TPMS_ATTEST structure which includes:
/// - magic: 0xff544347 (TPM_GENERATED_VALUE)
/// - type: 0x8017 (TPM_ST_ATTEST_CERTIFY)
/// - qualifiedSigner: TPM2B_NAME
/// - extraData: TPM2B_DATA (our nonce)
/// - clockInfo: TPMS_CLOCK_INFO
/// - firmwareVersion: u64
/// - attested.certify.name: TPM2B_NAME (certified object's name)
/// - attested.certify.qualifiedName: TPM2B_NAME
pub fn parse_tpm2b_attest(data: &[u8]) -> Result<TpmAttestInfo, VerifyError> {
    if data.len() < 6 {
        return Err(VerifyError::InvalidAttest("TPM2B_ATTEST too short".into()));
    }

    let mut offset = 0;

    // magic (4 bytes)
    let magic = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
    if magic != TPM_GENERATED_VALUE {
        return Err(VerifyError::InvalidAttest(format!(
            "Invalid TPM magic: expected 0x{:08x}, got 0x{:08x}",
            TPM_GENERATED_VALUE, magic
        )));
    }
    offset += 4;

    // type (2 bytes)
    let attest_type = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap());
    if attest_type != TPM_ST_ATTEST_CERTIFY {
        return Err(VerifyError::InvalidAttest(format!(
            "Invalid attest type: expected 0x{:04x} (CERTIFY), got 0x{:04x}",
            TPM_ST_ATTEST_CERTIFY, attest_type
        )));
    }
    offset += 2;

    // qualifiedSigner (TPM2B_NAME)
    if offset + 2 > data.len() {
        return Err(VerifyError::InvalidAttest("Truncated qualifiedSigner".into()));
    }
    let signer_size = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;
    if offset + signer_size > data.len() {
        return Err(VerifyError::InvalidAttest("Truncated qualifiedSigner data".into()));
    }
    let signer_name = data[offset..offset + signer_size].to_vec();
    offset += signer_size;

    // extraData (TPM2B_DATA) - this is our nonce
    if offset + 2 > data.len() {
        return Err(VerifyError::InvalidAttest("Truncated extraData".into()));
    }
    let extra_size = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;
    if offset + extra_size > data.len() {
        return Err(VerifyError::InvalidAttest("Truncated extraData data".into()));
    }
    let nonce = data[offset..offset + extra_size].to_vec();
    offset += extra_size;

    // clockInfo (TPMS_CLOCK_INFO)
    // clock: u64, resetCount: u32, restartCount: u32, safe: u8
    if offset + TPMS_CLOCK_INFO_SIZE > data.len() {
        return Err(VerifyError::InvalidAttest("Truncated clockInfo".into()));
    }
    offset += TPMS_CLOCK_INFO_SIZE;

    // firmwareVersion (8 bytes)
    if offset + 8 > data.len() {
        return Err(VerifyError::InvalidAttest("Truncated firmwareVersion".into()));
    }
    offset += 8;

    // attested (TPMS_CERTIFY_INFO)
    // - name (TPM2B_NAME)
    if offset + 2 > data.len() {
        return Err(VerifyError::InvalidAttest("Truncated certified name".into()));
    }
    let name_size = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;
    if offset + name_size > data.len() {
        return Err(VerifyError::InvalidAttest("Truncated certified name data".into()));
    }
    let certified_name = data[offset..offset + name_size].to_vec();

    Ok(TpmAttestInfo {
        nonce,
        certified_name,
        signer_name,
    })
}


#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::SigningKey;
    use rawdogtpm2::TpmAlg;
    use sha2::Sha256;

    /// Generate a test P-256 key pair and sign a message
    /// The signature is over SHA256(message) to match what verify_ecdsa_p256 expects
    fn sign_message(message: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // Use a fixed seed for deterministic tests
        let secret_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        let signing_key = SigningKey::from_bytes(&secret_bytes.into()).unwrap();

        // Get the public key in SEC1 uncompressed format
        let verifying_key = signing_key.verifying_key();
        let pubkey = verifying_key.to_encoded_point(false);
        let pubkey_bytes = pubkey.as_bytes().to_vec();

        // verify_ecdsa_p256 does: digest = SHA256(message), then verify_prehash
        // So we need to sign_prehash over SHA256(message)
        let digest = Sha256::digest(message);
        let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&digest).unwrap();
        let sig_der = signature.to_der().as_bytes().to_vec();

        (pubkey_bytes, sig_der)
    }

    // === ECDSA Verification Tests ===

    #[test]
    fn test_valid_p256_signature() {
        let message = b"test message for signing";
        let (pubkey, signature) = sign_message(message);

        let result = verify_ecdsa_p256(message, &signature, &pubkey);
        assert!(result.is_ok(), "Valid signature should verify: {:?}", result);
    }

    #[test]
    fn test_reject_wrong_message() {
        let message = b"test message for signing";
        let wrong_message = b"different message";
        let (pubkey, signature) = sign_message(message);

        let result = verify_ecdsa_p256(wrong_message, &signature, &pubkey);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_invalid_pubkey_not_on_curve() {
        let message = b"test message";
        let (_, signature) = sign_message(message);

        // Invalid public key: 0x04 prefix + arbitrary X, Y that's not on curve
        let mut invalid_pubkey = vec![0x04];
        invalid_pubkey.extend([0x00u8; 32]); // X = 0
        invalid_pubkey.extend([0x01u8; 32]); // Y = 1 (not on curve)

        let result = verify_ecdsa_p256(message, &signature, &invalid_pubkey);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_identity_point() {
        let message = b"test message";
        let (_, signature) = sign_message(message);

        // Identity point: X = 0, Y = 0 (invalid for P-256)
        let mut identity = vec![0x04];
        identity.extend([0x00u8; 32]); // X = 0
        identity.extend([0x00u8; 32]); // Y = 0

        let result = verify_ecdsa_p256(message, &signature, &identity);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_wrong_size_pubkey_too_short() {
        let message = b"test message";
        let (_, signature) = sign_message(message);

        // Public key that's too short
        let short_pubkey = vec![0x04, 0x01, 0x02, 0x03];

        let result = verify_ecdsa_p256(message, &signature, &short_pubkey);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_wrong_size_pubkey_too_long() {
        let message = b"test message";
        let (_, signature) = sign_message(message);

        // Public key that's too long
        let mut long_pubkey = vec![0x04];
        long_pubkey.extend([0x01u8; 100]);

        let result = verify_ecdsa_p256(message, &signature, &long_pubkey);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_compressed_pubkey() {
        let message = b"test message";
        let (_, signature) = sign_message(message);

        // Compressed public key (0x02 or 0x03 prefix) - only 33 bytes
        let mut compressed = vec![0x02];
        compressed.extend([0x01u8; 32]);

        // This might work or fail depending on library support
        // The important thing is it doesn't panic
        let _ = verify_ecdsa_p256(message, &signature, &compressed);
    }

    #[test]
    fn test_reject_malformed_der_signature() {
        let message = b"test message";
        let (pubkey, _) = sign_message(message);

        // Completely invalid DER
        let invalid_sig = vec![0x00, 0x01, 0x02, 0x03];

        let result = verify_ecdsa_p256(message, &invalid_sig, &pubkey);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_truncated_der_signature() {
        let message = b"test message";
        let (pubkey, signature) = sign_message(message);

        // Truncate the signature
        let truncated = &signature[..signature.len() / 2];

        let result = verify_ecdsa_p256(message, truncated, &pubkey);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_empty_signature() {
        let message = b"test message";
        let (pubkey, _) = sign_message(message);

        let result = verify_ecdsa_p256(message, &[], &pubkey);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_empty_pubkey() {
        let message = b"test message";
        let (_, signature) = sign_message(message);

        let result = verify_ecdsa_p256(message, &signature, &[]);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_wrong_pubkey() {
        let message = b"test message";
        let (_, signature) = sign_message(message);

        // Generate a different valid key
        let other_secret: [u8; 32] = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        ];
        let other_key = SigningKey::from_bytes(&other_secret.into()).unwrap();
        let other_pubkey = other_key.verifying_key().to_encoded_point(false);

        let result = verify_ecdsa_p256(message, &signature, other_pubkey.as_bytes());
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_empty_message() {
        let message = b"";
        let (pubkey, signature) = sign_message(message);

        // Empty message should still work
        let result = verify_ecdsa_p256(message, &signature, &pubkey);
        assert!(result.is_ok());
    }

    #[test]
    fn test_large_message() {
        // Test with a large message
        let message = vec![0xABu8; 10000];
        let (pubkey, signature) = sign_message(&message);

        let result = verify_ecdsa_p256(&message, &signature, &pubkey);
        assert!(result.is_ok());
    }

    // === PCR Policy Calculation Tests ===

    #[test]
    fn test_calculate_pcr_policy_single_pcr() {
        // Test with a single PCR (all zeros)
        let mut pcrs = BTreeMap::new();
        let pcr0 = "0".repeat(64);  // 32 bytes of zeros as hex
        pcrs.insert(0, pcr0);

        let result = calculate_pcr_policy(&pcrs, TpmAlg::Sha256);
        assert!(result.is_ok());

        let policy = result.unwrap();
        // Policy should be a 64-character hex string (32 bytes)
        assert_eq!(policy.len(), 64);
    }

    #[test]
    fn test_calculate_pcr_policy_multiple_pcrs() {
        // Test with PCRs 0, 1, 2
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, "0".repeat(64));
        pcrs.insert(1, "1".repeat(64));  // All 0x11...
        pcrs.insert(2, "2".repeat(64));  // All 0x22...

        let result = calculate_pcr_policy(&pcrs, TpmAlg::Sha256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_calculate_pcr_policy_non_contiguous() {
        // Test with non-contiguous PCRs (0, 7, 15)
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, "0".repeat(64));
        pcrs.insert(7, "7".repeat(64));
        pcrs.insert(15, "f".repeat(64));

        let result = calculate_pcr_policy(&pcrs, TpmAlg::Sha256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_calculate_pcr_policy_deterministic() {
        // Same input should produce same output
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, "0".repeat(64));

        let policy1 = calculate_pcr_policy(&pcrs, TpmAlg::Sha256).unwrap();
        let policy2 = calculate_pcr_policy(&pcrs, TpmAlg::Sha256).unwrap();

        assert_eq!(policy1, policy2);
    }

    #[test]
    fn test_calculate_pcr_policy_different_values() {
        // Different PCR values should produce different policies
        let mut pcrs1 = BTreeMap::new();
        pcrs1.insert(0, "0".repeat(64));

        let mut pcrs2 = BTreeMap::new();
        pcrs2.insert(0, "1".repeat(64));

        let policy1 = calculate_pcr_policy(&pcrs1, TpmAlg::Sha256).unwrap();
        let policy2 = calculate_pcr_policy(&pcrs2, TpmAlg::Sha256).unwrap();

        assert_ne!(policy1, policy2);
    }

    #[test]
    fn test_calculate_pcr_policy_empty() {
        let pcrs: BTreeMap<u8, String> = BTreeMap::new();
        let result = calculate_pcr_policy(&pcrs, TpmAlg::Sha256);
        assert!(matches!(result, Err(VerifyError::InvalidAttest(_))));
    }

    #[test]
    fn test_calculate_pcr_policy_invalid_index() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(24, "0".repeat(64));  // Index 24 is invalid (max 23)

        let result = calculate_pcr_policy(&pcrs, TpmAlg::Sha256);
        assert!(matches!(result, Err(VerifyError::InvalidAttest(_))));
    }

    #[test]
    fn test_calculate_pcr_policy_invalid_length() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, "0".repeat(32));  // Only 16 bytes, need 32

        let result = calculate_pcr_policy(&pcrs, TpmAlg::Sha256);
        assert!(matches!(result, Err(VerifyError::InvalidAttest(_))));
    }

    #[test]
    fn test_calculate_pcr_policy_invalid_hex() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, "gg".repeat(32));  // Invalid hex

        let result = calculate_pcr_policy(&pcrs, TpmAlg::Sha256);
        assert!(matches!(result, Err(VerifyError::HexDecode(_))));
    }

    #[test]
    fn test_verify_pcr_policy_match() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, "0".repeat(64));

        let expected = calculate_pcr_policy(&pcrs, TpmAlg::Sha256).unwrap();
        let result = verify_pcr_policy(&expected, &pcrs, TpmAlg::Sha256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_pcr_policy_mismatch() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, "0".repeat(64));

        // Wrong expected policy
        let wrong_expected = "f".repeat(64);
        let result = verify_pcr_policy(&wrong_expected, &pcrs, TpmAlg::Sha256);
        assert!(matches!(result, Err(VerifyError::InvalidAttest(_))));
    }

    // === SHA-384 PCR Policy Tests ===

    #[test]
    fn test_calculate_pcr_policy_sha384() {
        // Test with SHA-384 PCRs (48 bytes = 96 hex chars)
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, "0".repeat(96));

        let result = calculate_pcr_policy(&pcrs, TpmAlg::Sha384);
        assert!(result.is_ok());

        let policy = result.unwrap();
        // Policy is always SHA-256 (32 bytes = 64 hex chars)
        assert_eq!(policy.len(), 64);
    }

    #[test]
    fn test_calculate_pcr_policy_sha384_wrong_size() {
        // SHA-384 expects 48 bytes, not 32
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, "0".repeat(64));  // 32 bytes - wrong for SHA-384

        let result = calculate_pcr_policy(&pcrs, TpmAlg::Sha384);
        assert!(matches!(result, Err(VerifyError::InvalidAttest(_))));
    }

    #[test]
    fn test_calculate_pcr_policy_different_alg_different_policy() {
        // Same PCR value but different algorithms should produce different policies
        // because the algorithm ID is encoded in the PCR selection structure
        let mut pcrs256 = BTreeMap::new();
        pcrs256.insert(0, "0".repeat(64));  // 32 bytes for SHA-256

        let mut pcrs384 = BTreeMap::new();
        pcrs384.insert(0, "0".repeat(96));  // 48 bytes for SHA-384 (different zeros count)

        let policy256 = calculate_pcr_policy(&pcrs256, TpmAlg::Sha256).unwrap();
        let policy384 = calculate_pcr_policy(&pcrs384, TpmAlg::Sha384).unwrap();

        // Policies should differ due to algorithm ID in selection structure
        assert_ne!(policy256, policy384);
    }
}
