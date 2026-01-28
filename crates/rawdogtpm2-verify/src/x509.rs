// SPDX-License-Identifier: MIT OR Apache-2.0

//! X.509 certificate handling

use der::Decode;
use ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

use crate::error::VerifyError;

/// Parse X.509 certificate chain from PEM format
///
/// Returns certificates in order from the PEM file (typically leaf first, root last)
pub fn parse_cert_chain_pem(pem: &str) -> Result<Vec<Certificate>, VerifyError> {
    let mut certs = Vec::new();
    let mut current_cert = String::new();
    let mut in_cert = false;

    for line in pem.lines() {
        if line.contains("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current_cert.clear();
        } else if line.contains("-----END CERTIFICATE-----") {
            in_cert = false;
            // Decode the certificate
            let der_bytes = base64_decode(&current_cert)?;
            let cert = Certificate::from_der(&der_bytes)
                .map_err(|e| VerifyError::CertificateParse(e.to_string()))?;
            certs.push(cert);
        } else if in_cert {
            current_cert.push_str(line.trim());
        }
    }

    if certs.is_empty() {
        return Err(VerifyError::CertificateParse(
            "No certificates found in PEM".into(),
        ));
    }

    Ok(certs)
}

/// Simple base64 decoder
pub(crate) fn base64_decode(input: &str) -> Result<Vec<u8>, VerifyError> {
    use std::collections::HashMap;

    let alphabet: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let decode_table: HashMap<u8, u8> = alphabet
        .iter()
        .enumerate()
        .map(|(i, &c)| (c, i as u8))
        .collect();

    let input: Vec<u8> = input.bytes().filter(|&b| b != b'\n' && b != b'\r').collect();
    let mut output = Vec::new();

    for chunk in input.chunks(4) {
        let mut buf = [0u8; 4];
        let mut valid = 0;

        for (i, &byte) in chunk.iter().enumerate() {
            if byte == b'=' {
                break;
            }
            buf[i] = *decode_table
                .get(&byte)
                .ok_or_else(|| VerifyError::CertificateParse("Invalid base64".into()))?;
            valid += 1;
        }

        if valid >= 2 {
            output.push((buf[0] << 2) | (buf[1] >> 4));
        }
        if valid >= 3 {
            output.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if valid >= 4 {
            output.push((buf[2] << 6) | buf[3]);
        }
    }

    Ok(output)
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

/// Validate a certificate chain
///
/// Verifies that each certificate's signature can be verified by the next certificate
/// in the chain (the issuer). The last certificate is assumed to be self-signed or a root.
pub fn validate_cert_chain(chain: &[Certificate]) -> Result<(), VerifyError> {
    if chain.is_empty() {
        return Err(VerifyError::ChainValidation("Empty certificate chain".into()));
    }

    // For each certificate except the last, verify it was signed by the next
    for i in 0..chain.len().saturating_sub(1) {
        let cert = &chain[i];
        let issuer = &chain[i + 1];
        verify_certificate_signature(cert, issuer)?;
    }

    Ok(())
}

/// Verify that a certificate was signed by the issuer
pub(crate) fn verify_certificate_signature(
    cert: &Certificate,
    issuer: &Certificate,
) -> Result<(), VerifyError> {
    use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
    use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};

    // Get the issuer's public key
    let issuer_pubkey = extract_public_key(issuer)?;

    // Get the signature from the certificate
    let sig_bytes = cert
        .signature
        .as_bytes()
        .ok_or_else(|| VerifyError::ChainValidation("Invalid signature bits".into()))?;

    // Get the TBS (to-be-signed) certificate data
    let tbs_der = der::Encode::to_der(&cert.tbs_certificate)
        .map_err(|e| VerifyError::ChainValidation(format!("Failed to encode TBS: {}", e)))?;

    // Determine the signature algorithm
    let sig_alg = &cert.signature_algorithm;
    let alg_oid = sig_alg.oid.to_string();

    // ecdsa-with-SHA256: 1.2.840.10045.4.3.2
    // ecdsa-with-SHA384: 1.2.840.10045.4.3.3
    // ecdsa-with-SHA512: 1.2.840.10045.4.3.4
    match alg_oid.as_str() {
        "1.2.840.10045.4.3.2" => {
            // ECDSA with SHA-256 (P-256)
            let verifying_key = P256VerifyingKey::from_sec1_bytes(&issuer_pubkey)
                .map_err(|e| VerifyError::ChainValidation(format!("Invalid P-256 key: {}", e)))?;
            let signature = P256Signature::from_der(sig_bytes)
                .map_err(|e| VerifyError::ChainValidation(format!("Invalid signature: {}", e)))?;
            let digest = Sha256::digest(&tbs_der);
            verifying_key
                .verify_prehash(&digest, &signature)
                .map_err(|e| VerifyError::ChainValidation(format!("Signature invalid: {}", e)))?;
        }
        "1.2.840.10045.4.3.3" => {
            // ECDSA with SHA-384 (P-384)
            let verifying_key = P384VerifyingKey::from_sec1_bytes(&issuer_pubkey)
                .map_err(|e| VerifyError::ChainValidation(format!("Invalid P-384 key: {}", e)))?;
            let signature = P384Signature::from_der(sig_bytes)
                .map_err(|e| VerifyError::ChainValidation(format!("Invalid signature: {}", e)))?;
            // SHA-384 digest
            use sha2::Sha384;
            let digest = Sha384::digest(&tbs_der);
            verifying_key
                .verify_prehash(&digest, &signature)
                .map_err(|e| VerifyError::ChainValidation(format!("Signature invalid: {}", e)))?;
        }
        _ => {
            return Err(VerifyError::UnsupportedAlgorithm(format!(
                "Unsupported signature algorithm OID: {}",
                alg_oid
            )));
        }
    }

    Ok(())
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
        let decoded = base64_decode(input).unwrap();
        assert_eq!(decoded, b"Hello World");
    }
}
