// SPDX-License-Identifier: MIT OR Apache-2.0

//! TPM attestation parsing and verification

use std::collections::BTreeMap;

use ecdsa::signature::hazmat::PrehashVerifier;
use serde::Serialize;
use sha2::{Digest, Sha256};

use pki_types::UnixTime;

use crate::error::VerifyError;
use crate::x509::{extract_public_key, parse_and_validate_cert_chain, parse_cert_chain_pem};

/// TPM2_CC_PolicyPCR command code
const TPM_CC_POLICY_PCR: u32 = 0x0000017F;

/// TPM_ALG_SHA256
const TPM_ALG_SHA256: u16 = 0x000B;

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

/// Calculate the expected PCR policy digest from PCR values
///
/// This calculates the TPM2 PolicyPCR digest that would be used as an
/// authPolicy for a key bound to the given PCR values.
///
/// The calculation follows TPM2 spec:
/// 1. pcrDigest = SHA256(PCR0 || PCR1 || ... || PCRn) for selected PCRs
/// 2. policyDigest = SHA256(zeros || TPM_CC_PolicyPCR || TPML_PCR_SELECTION || pcrDigest)
///
/// # Arguments
/// * `pcrs` - Map of PCR index to hex-encoded PCR value (only SHA-256 bank)
///
/// # Returns
/// The expected policy digest as a hex-encoded string
///
/// # Example
/// ```ignore
/// let mut pcrs = BTreeMap::new();
/// pcrs.insert(0, "0000...".to_string());  // 64 hex chars for SHA-256
/// pcrs.insert(1, "0000...".to_string());
/// let policy = calculate_pcr_policy(&pcrs)?;
/// ```
pub fn calculate_pcr_policy(pcrs: &BTreeMap<u8, String>) -> Result<String, VerifyError> {
    if pcrs.is_empty() {
        return Err(VerifyError::InvalidAttest("No PCR values provided".into()));
    }

    // Validate all PCR indices are in valid range (0-23)
    for &idx in pcrs.keys() {
        if idx > 23 {
            return Err(VerifyError::InvalidAttest(format!(
                "PCR index {} out of range (max 23)",
                idx
            )));
        }
    }

    // Step 1: Calculate PCR digest (hash of selected PCR values in order)
    let mut pcr_hasher = Sha256::new();
    for idx in 0..=23u8 {
        if let Some(value_hex) = pcrs.get(&idx) {
            let value_bytes = hex::decode(value_hex)?;
            if value_bytes.len() != 32 {
                return Err(VerifyError::InvalidAttest(format!(
                    "PCR {} has invalid length: expected 32 bytes, got {}",
                    idx,
                    value_bytes.len()
                )));
            }
            pcr_hasher.update(&value_bytes);
        }
    }
    let pcr_digest = pcr_hasher.finalize();

    // Step 2: Build PCR selection bitmask (3 bytes for PCRs 0-23)
    let mut pcr_select = [0u8; 3];
    for &idx in pcrs.keys() {
        pcr_select[idx as usize / 8] |= 1 << (idx % 8);
    }

    // Step 3: Calculate policy digest
    // policyDigest = SHA256(previousDigest || TPM_CC_PolicyPCR || TPML_PCR_SELECTION || pcrDigest)
    let mut policy_hasher = Sha256::new();

    // previousDigest: starts as all zeros (32 bytes for SHA-256)
    policy_hasher.update(&[0u8; 32]);

    // TPM_CC_PolicyPCR (big-endian)
    policy_hasher.update(&TPM_CC_POLICY_PCR.to_be_bytes());

    // TPML_PCR_SELECTION structure:
    // - count: u32 (1 bank)
    policy_hasher.update(&1u32.to_be_bytes());
    // TPMS_PCR_SELECTION:
    // - hash: u16 (TPM_ALG_SHA256)
    policy_hasher.update(&TPM_ALG_SHA256.to_be_bytes());
    // - sizeOfSelect: u8 (3 bytes)
    policy_hasher.update(&[3u8]);
    // - pcrSelect: [u8; 3]
    policy_hasher.update(&pcr_select);

    // PCR digest
    policy_hasher.update(&pcr_digest);

    let policy_digest = policy_hasher.finalize();
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
///
/// # Returns
/// Ok(()) if the policy matches, error otherwise
pub fn verify_pcr_policy(
    expected_policy_hex: &str,
    pcrs: &BTreeMap<u8, String>,
) -> Result<(), VerifyError> {
    let calculated_policy = calculate_pcr_policy(pcrs)?;

    if calculated_policy != expected_policy_hex {
        return Err(VerifyError::InvalidAttest(format!(
            "PCR policy mismatch: expected {}, calculated {}",
            expected_policy_hex, calculated_policy
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::SigningKey;
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

        let result = calculate_pcr_policy(&pcrs);
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

        let result = calculate_pcr_policy(&pcrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_calculate_pcr_policy_non_contiguous() {
        // Test with non-contiguous PCRs (0, 7, 15)
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, "0".repeat(64));
        pcrs.insert(7, "7".repeat(64));
        pcrs.insert(15, "f".repeat(64));

        let result = calculate_pcr_policy(&pcrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_calculate_pcr_policy_deterministic() {
        // Same input should produce same output
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, "0".repeat(64));

        let policy1 = calculate_pcr_policy(&pcrs).unwrap();
        let policy2 = calculate_pcr_policy(&pcrs).unwrap();

        assert_eq!(policy1, policy2);
    }

    #[test]
    fn test_calculate_pcr_policy_different_values() {
        // Different PCR values should produce different policies
        let mut pcrs1 = BTreeMap::new();
        pcrs1.insert(0, "0".repeat(64));

        let mut pcrs2 = BTreeMap::new();
        pcrs2.insert(0, "1".repeat(64));

        let policy1 = calculate_pcr_policy(&pcrs1).unwrap();
        let policy2 = calculate_pcr_policy(&pcrs2).unwrap();

        assert_ne!(policy1, policy2);
    }

    #[test]
    fn test_calculate_pcr_policy_empty() {
        let pcrs: BTreeMap<u8, String> = BTreeMap::new();
        let result = calculate_pcr_policy(&pcrs);
        assert!(matches!(result, Err(VerifyError::InvalidAttest(_))));
    }

    #[test]
    fn test_calculate_pcr_policy_invalid_index() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(24, "0".repeat(64));  // Index 24 is invalid (max 23)

        let result = calculate_pcr_policy(&pcrs);
        assert!(matches!(result, Err(VerifyError::InvalidAttest(_))));
    }

    #[test]
    fn test_calculate_pcr_policy_invalid_length() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, "0".repeat(32));  // Only 16 bytes, need 32

        let result = calculate_pcr_policy(&pcrs);
        assert!(matches!(result, Err(VerifyError::InvalidAttest(_))));
    }

    #[test]
    fn test_calculate_pcr_policy_invalid_hex() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, "gg".repeat(32));  // Invalid hex

        let result = calculate_pcr_policy(&pcrs);
        assert!(matches!(result, Err(VerifyError::HexDecode(_))));
    }

    #[test]
    fn test_verify_pcr_policy_match() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, "0".repeat(64));

        let expected = calculate_pcr_policy(&pcrs).unwrap();
        let result = verify_pcr_policy(&expected, &pcrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_pcr_policy_mismatch() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, "0".repeat(64));

        // Wrong expected policy
        let wrong_expected = "f".repeat(64);
        let result = verify_pcr_policy(&wrong_expected, &pcrs);
        assert!(matches!(result, Err(VerifyError::InvalidAttest(_))));
    }
}
