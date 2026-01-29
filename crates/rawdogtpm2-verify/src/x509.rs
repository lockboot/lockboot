// SPDX-License-Identifier: MIT OR Apache-2.0

//! X.509 certificate handling using rustls-webpki for chain validation

use base64::{engine::general_purpose::STANDARD, Engine as _};
use der::{Decode, Encode};
use pki_types::{CertificateDer, UnixTime};
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

use crate::error::VerifyError;

/// Maximum allowed certificate chain depth (to prevent DoS)
pub const MAX_CHAIN_DEPTH: usize = 10;

/// PEM certificate begin marker
const PEM_CERT_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
/// PEM certificate end marker
const PEM_CERT_END: &str = "-----END CERTIFICATE-----";

/// Parse X.509 certificate chain from PEM format
///
/// Returns certificates in order from the PEM file (typically leaf first, root last).
///
/// This parser is strict about:
/// - Exact BEGIN/END markers (not just "contains")
/// - No non-whitespace data between certificates
/// - Valid base64 content within certificate blocks
pub fn parse_cert_chain_pem(pem: &str) -> Result<Vec<Certificate>, VerifyError> {
    let mut certs = Vec::new();
    let mut current_cert = String::new();
    let mut in_cert = false;
    let mut line_number = 0;

    for line in pem.lines() {
        line_number += 1;
        let trimmed = line.trim();

        // Check for BEGIN marker
        if trimmed == PEM_CERT_BEGIN {
            if in_cert {
                return Err(VerifyError::CertificateParse(format!(
                    "Line {}: Unexpected BEGIN marker inside certificate block",
                    line_number
                )));
            }
            in_cert = true;
            current_cert.clear();
            continue;
        }

        // Check for END marker
        if trimmed == PEM_CERT_END {
            if !in_cert {
                return Err(VerifyError::CertificateParse(format!(
                    "Line {}: END marker without matching BEGIN",
                    line_number
                )));
            }
            in_cert = false;

            // Decode the certificate
            if current_cert.is_empty() {
                return Err(VerifyError::CertificateParse(format!(
                    "Line {}: Empty certificate content",
                    line_number
                )));
            }

            let der_bytes = base64_decode(&current_cert)?;
            let cert = Certificate::from_der(&der_bytes)
                .map_err(|e| VerifyError::CertificateParse(format!(
                    "Line {}: Invalid DER: {}",
                    line_number, e
                )))?;
            certs.push(cert);
            continue;
        }

        // Inside a certificate block: accumulate base64 content
        if in_cert {
            // Validate that line contains only base64 characters
            if !trimmed.is_empty() && !is_valid_base64_line(trimmed) {
                return Err(VerifyError::CertificateParse(format!(
                    "Line {}: Invalid base64 character in certificate",
                    line_number
                )));
            }
            current_cert.push_str(trimmed);
            continue;
        }

        // Outside certificate blocks: only whitespace is allowed
        if !trimmed.is_empty() {
            return Err(VerifyError::CertificateParse(format!(
                "Line {}: Unexpected content outside certificate block: '{}'",
                line_number,
                if trimmed.len() > 20 { &trimmed[..20] } else { trimmed }
            )));
        }
    }

    // Check for unclosed certificate block
    if in_cert {
        return Err(VerifyError::CertificateParse(
            "Unclosed certificate block (missing END marker)".into(),
        ));
    }

    if certs.is_empty() {
        return Err(VerifyError::CertificateParse(
            "No certificates found in PEM".into(),
        ));
    }

    Ok(certs)
}

/// Check if a string contains only valid base64 characters
fn is_valid_base64_line(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// Decode base64 string
fn base64_decode(input: &str) -> Result<Vec<u8>, VerifyError> {
    STANDARD
        .decode(input)
        .map_err(|e| VerifyError::CertificateParse(format!("Invalid base64: {}", e)))
}

/// Extract raw public key bytes from an X.509 certificate
///
/// Returns the SubjectPublicKeyInfo's bit string contents
pub fn extract_public_key(cert: &Certificate) -> Result<Vec<u8>, VerifyError> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let pubkey_bits = spki.subject_public_key.as_bytes().ok_or_else(|| {
        VerifyError::CertificateParse("Public key has unused bits".into())
    })?;
    Ok(pubkey_bits.to_vec())
}

/// Compute SHA-256 hash of public key and return as hex string
pub fn hash_public_key(pubkey_bytes: &[u8]) -> String {
    let digest = Sha256::digest(pubkey_bytes);
    hex::encode(digest)
}

/// Result of certificate chain validation
#[derive(Debug)]
pub struct ChainValidationResult {
    /// SHA-256 hash of the root CA's public key (hex string)
    pub root_pubkey_hash: String,
}

/// Validate a certificate chain using webpki
///
/// Chain should be leaf-first, root-last. Time must be provided by caller.
pub fn validate_cert_chain(
    chain: &[Certificate],
    time: UnixTime,
) -> Result<ChainValidationResult, VerifyError> {
    if chain.is_empty() {
        return Err(VerifyError::ChainValidation("Empty certificate chain".into()));
    }
    if chain.len() > MAX_CHAIN_DEPTH {
        return Err(VerifyError::ChainValidation(format!(
            "Certificate chain too deep: {} certificates (max {})",
            chain.len(),
            MAX_CHAIN_DEPTH
        )));
    }

    // Get signature verification algorithms from rustls-rustcrypto
    let sig_algs = rustls_rustcrypto::provider()
        .signature_verification_algorithms
        .all;

    // Convert to DER format for webpki
    let cert_ders: Vec<CertificateDer> = chain
        .iter()
        .map(|c| {
            let der = c.to_der().map_err(|e| {
                VerifyError::CertificateParse(format!("Failed to encode cert to DER: {}", e))
            })?;
            Ok(CertificateDer::from(der))
        })
        .collect::<Result<Vec<_>, VerifyError>>()?;

    // Root is last in chain - create trust anchor from it
    let root_der = &cert_ders[cert_ders.len() - 1];
    let trust_anchor = anchor_from_trusted_cert(root_der)
        .map_err(|e| VerifyError::ChainValidation(format!("Invalid root certificate: {:?}", e)))?;

    // Leaf is first
    let ee_cert = EndEntityCert::try_from(&cert_ders[0])
        .map_err(|e| VerifyError::CertificateParse(format!("Invalid leaf certificate: {:?}", e)))?;

    // Intermediates are everything between leaf and root
    let intermediates: Vec<CertificateDer> = if cert_ders.len() > 2 {
        cert_ders[1..cert_ders.len() - 1].to_vec()
    } else {
        Vec::new()
    };

    // Use webpki to verify the chain
    ee_cert
        .verify_for_usage(
            sig_algs,
            &[trust_anchor],
            &intermediates,
            time,
            KeyUsage::client_auth(),
            None, // no revocation checking
            None, // no custom path verification
        )
        .map_err(|e| VerifyError::ChainValidation(format!("Chain validation failed: {:?}", e)))?;

    // Extract and hash root's public key
    let root_pubkey = extract_public_key(&chain[chain.len() - 1])?;
    let root_hash = hash_public_key(&root_pubkey);

    Ok(ChainValidationResult {
        root_pubkey_hash: root_hash,
    })
}

/// Parse PEM and validate certificate chain
///
/// Convenience wrapper that parses PEM then validates.
/// Chain should be leaf-first, root-last in the PEM.
pub fn parse_and_validate_cert_chain(
    chain_pem: &str,
    time: UnixTime,
) -> Result<ChainValidationResult, VerifyError> {
    let certs = parse_cert_chain_pem(chain_pem)?;
    validate_cert_chain(&certs, time)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_public_key() {
        let pubkey = [0x04, 0x01, 0x02, 0x03];
        let hash = hash_public_key(&pubkey);
        // SHA-256 of [0x04, 0x01, 0x02, 0x03]
        assert_eq!(hash.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_base64_decode() {
        let input = "SGVsbG8gV29ybGQ="; // "Hello World"
        let decoded = STANDARD.decode(input).unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    // === PEM Parsing Edge Cases ===

    #[test]
    fn test_reject_no_certificates() {
        let pem = "This is not a PEM file at all";
        let result = parse_cert_chain_pem(pem);
        assert!(matches!(result, Err(VerifyError::CertificateParse(_))));
    }

    #[test]
    fn test_reject_empty_pem() {
        let pem = "";
        let result = parse_cert_chain_pem(pem);
        assert!(matches!(result, Err(VerifyError::CertificateParse(_))));
    }

    #[test]
    fn test_reject_missing_end_marker() {
        let pem = "-----BEGIN CERTIFICATE-----\nMIIB";
        let result = parse_cert_chain_pem(pem);
        // Should fail because no END marker means no certificate is completed
        assert!(matches!(result, Err(VerifyError::CertificateParse(_))));
    }

    #[test]
    fn test_reject_empty_certificate_content() {
        let pem = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----";
        let result = parse_cert_chain_pem(pem);
        // Empty base64 content should fail DER parsing
        assert!(matches!(result, Err(VerifyError::CertificateParse(_))));
    }

    #[test]
    fn test_reject_invalid_base64() {
        let pem = "-----BEGIN CERTIFICATE-----\n\
                   !!!invalid base64!!!\n\
                   -----END CERTIFICATE-----";
        let result = parse_cert_chain_pem(pem);
        assert!(matches!(result, Err(VerifyError::CertificateParse(_))));
    }

    #[test]
    fn test_reject_truncated_base64() {
        // Valid base64 prefix but incomplete (missing padding)
        let pem = "-----BEGIN CERTIFICATE-----\n\
                   MIIB\n\
                   -----END CERTIFICATE-----";
        let result = parse_cert_chain_pem(pem);
        // Should fail either in base64 decode or DER parse
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_invalid_der() {
        // Valid base64, but not valid DER certificate
        let pem = "-----BEGIN CERTIFICATE-----\n\
                   SGVsbG8gV29ybGQ=\n\
                   -----END CERTIFICATE-----";
        let result = parse_cert_chain_pem(pem);
        assert!(matches!(result, Err(VerifyError::CertificateParse(_))));
    }

    // === Strict PEM Parsing Tests ===

    #[test]
    fn test_reject_garbage_between_markers() {
        // Non-whitespace data outside certificate blocks should be rejected
        // This tests that the parser rejects garbage BEFORE any cert
        let pem = "garbage data here\n\
                   -----BEGIN CERTIFICATE-----\n\
                   SGVsbG8=\n\
                   -----END CERTIFICATE-----";
        let result = parse_cert_chain_pem(pem);
        assert!(matches!(result, Err(VerifyError::CertificateParse(ref msg)) if msg.contains("Unexpected content")));
    }

    #[test]
    fn test_allow_whitespace_between_certs() {
        // Whitespace between certificates should be allowed (though certs themselves are invalid DER)
        let pem = "-----BEGIN CERTIFICATE-----\n\
                   SGVsbG8=\n\
                   -----END CERTIFICATE-----\n\
                   \n\
                   \n\
                   -----BEGIN CERTIFICATE-----\n\
                   V29ybGQ=\n\
                   -----END CERTIFICATE-----";
        let result = parse_cert_chain_pem(pem);
        // Will fail on invalid DER, not on parsing
        assert!(matches!(result, Err(VerifyError::CertificateParse(ref msg)) if msg.contains("DER")));
    }

    #[test]
    fn test_reject_nested_begin_marker() {
        // Nested BEGIN marker should be rejected
        let pem = "-----BEGIN CERTIFICATE-----\n\
                   SGVsbG8=\n\
                   -----BEGIN CERTIFICATE-----\n\
                   V29ybGQ=\n\
                   -----END CERTIFICATE-----";
        let result = parse_cert_chain_pem(pem);
        assert!(matches!(result, Err(VerifyError::CertificateParse(ref msg)) if msg.contains("Unexpected BEGIN")));
    }

    #[test]
    fn test_reject_end_without_begin() {
        // END marker without BEGIN should be rejected
        let pem = "-----END CERTIFICATE-----";
        let result = parse_cert_chain_pem(pem);
        assert!(matches!(result, Err(VerifyError::CertificateParse(ref msg)) if msg.contains("without matching BEGIN")));
    }

    #[test]
    fn test_reject_unclosed_block() {
        // Unclosed certificate block should be rejected
        let pem = "-----BEGIN CERTIFICATE-----\n\
                   SGVsbG8=\n";
        let result = parse_cert_chain_pem(pem);
        assert!(matches!(result, Err(VerifyError::CertificateParse(ref msg)) if msg.contains("missing END")));
    }

    #[test]
    fn test_is_valid_base64_line() {
        assert!(is_valid_base64_line("ABCDabcd0123+/=="));
        assert!(!is_valid_base64_line("ABC!@#"));
        assert!(!is_valid_base64_line("ABC DEF"));  // space not allowed
        assert!(is_valid_base64_line(""));  // empty is valid
    }
}
