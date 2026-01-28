// SPDX-License-Identifier: MIT OR Apache-2.0

//! AWS Nitro Enclave attestation verification

use std::collections::BTreeMap;

use ciborium::Value as CborValue;
use coset::{CborSerializable, CoseSign1, TaggedCborSerializable};
use der::Decode;
use ecdsa::signature::hazmat::PrehashVerifier;
use serde::Serialize;
use sha2::{Digest, Sha384};
use x509_cert::Certificate;

use crate::error::VerifyError;
use crate::x509::{extract_public_key, hash_public_key, validate_cert_chain};

/// Result of successful Nitro attestation verification
///
/// This struct is only returned when verification succeeds.
/// If signature or chain validation fails, an error is returned instead.
#[derive(Debug, Serialize)]
pub struct NitroVerifyResult {
    /// Parsed attestation document fields
    pub document: NitroDocument,
    /// SHA-256 hash of the root CA's public key (hex string)
    pub root_pubkey_hash: String,
}

/// Parsed Nitro attestation document
#[derive(Debug, Serialize, Clone)]
pub struct NitroDocument {
    /// Module ID
    pub module_id: String,
    /// Timestamp (milliseconds since epoch)
    pub timestamp: u64,
    /// PCR values (index -> hex digest)
    pub pcrs: BTreeMap<u8, String>,
    /// Public key (hex-encoded, if provided)
    pub public_key: Option<String>,
    /// User data (hex-encoded, if provided)
    pub user_data: Option<String>,
    /// Nonce (hex-encoded, if provided)
    pub nonce: Option<String>,
    /// Digest algorithm used
    pub digest: String,
}

/// Verify Nitro attestation document
///
/// # Arguments
/// * `document_hex` - CBOR-encoded COSE Sign1 attestation document as hex string
/// * `expected_nonce` - Expected nonce value (optional validation)
/// * `expected_pubkey_hex` - Expected public key in SECG format (optional validation)
///
/// # Returns
/// Verification result with parsed document and root public key hash
pub fn verify_nitro_attestation(
    document_hex: &str,
    expected_nonce: Option<&[u8]>,
    expected_pubkey_hex: Option<&str>,
) -> Result<NitroVerifyResult, VerifyError> {
    // Decode hex input
    let document_bytes = hex::decode(document_hex)?;

    // Parse the COSE Sign1 structure
    let cose_sign1 = CoseSign1::from_tagged_slice(&document_bytes)
        .map_err(|e| VerifyError::CoseVerify(format!("Failed to parse COSE Sign1: {}", e)))?;

    // Extract the payload
    let payload = cose_sign1
        .payload
        .as_ref()
        .ok_or_else(|| VerifyError::CoseVerify("Missing payload".into()))?;

    // Parse payload as CBOR
    let doc_value: CborValue = ciborium::from_reader(payload.as_slice())
        .map_err(|e| VerifyError::CborParse(format!("Failed to parse payload: {}", e)))?;

    // Extract document fields
    let doc_map = match &doc_value {
        CborValue::Map(m) => m,
        _ => return Err(VerifyError::CborParse("Payload is not a map".into())),
    };

    let nitro_doc = parse_nitro_document(doc_map)?;

    // Validate nonce if provided
    if let Some(expected) = expected_nonce {
        if let Some(ref nonce_hex) = nitro_doc.nonce {
            let nonce_bytes = hex::decode(nonce_hex)?;
            if nonce_bytes != expected {
                return Err(VerifyError::CoseVerify("Nonce mismatch".into()));
            }
        }
    }

    // Validate public key if provided
    if let Some(expected_pk) = expected_pubkey_hex {
        if let Some(ref pk) = nitro_doc.public_key {
            if pk != expected_pk {
                return Err(VerifyError::CoseVerify("Public key mismatch".into()));
            }
        }
    }

    // Extract certificate and CA bundle
    let cert_der = extract_cbor_bytes(doc_map, "certificate")?;
    let cabundle = extract_cbor_byte_array(doc_map, "cabundle")?;

    // Parse certificates
    let leaf_cert = Certificate::from_der(&cert_der)
        .map_err(|e| VerifyError::CertificateParse(format!("Invalid leaf cert: {}", e)))?;

    let mut chain = vec![leaf_cert];
    for ca_der in cabundle {
        let ca_cert = Certificate::from_der(&ca_der)
            .map_err(|e| VerifyError::CertificateParse(format!("Invalid CA cert: {}", e)))?;
        chain.push(ca_cert);
    }

    // Validate certificate chain (fails on error)
    validate_cert_chain(&chain)?;

    // Verify COSE signature using leaf certificate (fails on error)
    let leaf_pubkey = extract_public_key(&chain[0])?;
    verify_cose_signature(&cose_sign1, &leaf_pubkey, payload)?;

    // Get root public key hash
    let root_cert = chain.last().ok_or_else(|| {
        VerifyError::ChainValidation("Empty certificate chain".into())
    })?;
    let root_pubkey = extract_public_key(root_cert)?;
    let root_pubkey_hash = hash_public_key(&root_pubkey);

    Ok(NitroVerifyResult {
        document: nitro_doc,
        root_pubkey_hash,
    })
}

/// Parse Nitro document fields from CBOR map
fn parse_nitro_document(
    map: &[(CborValue, CborValue)],
) -> Result<NitroDocument, VerifyError> {
    let module_id = extract_cbor_text(map, "module_id")?;
    let timestamp = extract_cbor_integer(map, "timestamp")?;
    let digest = extract_cbor_text(map, "digest")?;

    // Parse PCRs
    let pcrs = extract_cbor_pcrs(map)?;

    // Optional fields
    let public_key = extract_cbor_bytes_optional(map, "public_key").map(|b| hex::encode(&b));
    let user_data = extract_cbor_bytes_optional(map, "user_data").map(|b| hex::encode(&b));
    let nonce = extract_cbor_bytes_optional(map, "nonce").map(|b| hex::encode(&b));

    Ok(NitroDocument {
        module_id,
        timestamp,
        pcrs,
        public_key,
        user_data,
        nonce,
        digest,
    })
}

/// Extract text field from CBOR map
fn extract_cbor_text(map: &[(CborValue, CborValue)], key: &str) -> Result<String, VerifyError> {
    for (k, v) in map {
        if let CborValue::Text(k_text) = k {
            if k_text == key {
                if let CborValue::Text(val) = v {
                    return Ok(val.clone());
                }
            }
        }
    }
    Err(VerifyError::CborParse(format!("Missing field: {}", key)))
}

/// Extract integer field from CBOR map
fn extract_cbor_integer(map: &[(CborValue, CborValue)], key: &str) -> Result<u64, VerifyError> {
    for (k, v) in map {
        if let CborValue::Text(k_text) = k {
            if k_text == key {
                if let CborValue::Integer(val) = v {
                    let val_i128: i128 = (*val).into();
                    return Ok(val_i128 as u64);
                }
            }
        }
    }
    Err(VerifyError::CborParse(format!("Missing field: {}", key)))
}

/// Extract bytes field from CBOR map
fn extract_cbor_bytes(map: &[(CborValue, CborValue)], key: &str) -> Result<Vec<u8>, VerifyError> {
    for (k, v) in map {
        if let CborValue::Text(k_text) = k {
            if k_text == key {
                if let CborValue::Bytes(val) = v {
                    return Ok(val.clone());
                }
            }
        }
    }
    Err(VerifyError::CborParse(format!("Missing field: {}", key)))
}

/// Extract optional bytes field from CBOR map
fn extract_cbor_bytes_optional(map: &[(CborValue, CborValue)], key: &str) -> Option<Vec<u8>> {
    for (k, v) in map {
        if let CborValue::Text(k_text) = k {
            if k_text == key {
                if let CborValue::Bytes(val) = v {
                    return Some(val.clone());
                }
                if let CborValue::Null = v {
                    return None;
                }
            }
        }
    }
    None
}

/// Extract byte array field from CBOR map
fn extract_cbor_byte_array(
    map: &[(CborValue, CborValue)],
    key: &str,
) -> Result<Vec<Vec<u8>>, VerifyError> {
    for (k, v) in map {
        if let CborValue::Text(k_text) = k {
            if k_text == key {
                if let CborValue::Array(arr) = v {
                    let mut result = Vec::new();
                    for item in arr {
                        if let CborValue::Bytes(b) = item {
                            result.push(b.clone());
                        }
                    }
                    return Ok(result);
                }
            }
        }
    }
    Err(VerifyError::CborParse(format!("Missing field: {}", key)))
}

/// Extract PCRs from CBOR map
fn extract_cbor_pcrs(map: &[(CborValue, CborValue)]) -> Result<BTreeMap<u8, String>, VerifyError> {
    for (k, v) in map {
        if let CborValue::Text(k_text) = k {
            if k_text == "pcrs" {
                if let CborValue::Map(pcr_map) = v {
                    let mut pcrs = BTreeMap::new();
                    for (pk, pv) in pcr_map {
                        if let CborValue::Integer(idx) = pk {
                            if let CborValue::Bytes(val) = pv {
                                let idx_i128: i128 = (*idx).into();
                                pcrs.insert(idx_i128 as u8, hex::encode(val));
                            }
                        }
                    }
                    return Ok(pcrs);
                }
            }
        }
    }
    Err(VerifyError::CborParse("Missing pcrs field".into()))
}

/// Verify COSE Sign1 signature
fn verify_cose_signature(
    cose: &CoseSign1,
    public_key: &[u8],
    payload: &[u8],
) -> Result<(), VerifyError> {
    use p384::ecdsa::{Signature, VerifyingKey};

    // Nitro uses ES384 (ECDSA with P-384 and SHA-384)
    // Build the Sig_structure for COSE_Sign1:
    // Sig_structure = [
    //   context : "Signature1",
    //   body_protected : protected,
    //   external_aad : bstr,
    //   payload : bstr
    // ]

    // Get the protected header bytes using coset's serialization
    let protected = cose.protected.clone().to_vec()
        .map_err(|e| VerifyError::CoseVerify(format!("Failed to serialize protected header: {}", e)))?;

    let sig_structure = CborValue::Array(vec![
        CborValue::Text("Signature1".to_string()),
        CborValue::Bytes(protected),
        CborValue::Bytes(vec![]), // external_aad
        CborValue::Bytes(payload.to_vec()),
    ]);

    let mut sig_structure_bytes = Vec::new();
    ciborium::into_writer(&sig_structure, &mut sig_structure_bytes)
        .map_err(|e| VerifyError::CoseVerify(format!("Failed to encode Sig_structure: {}", e)))?;

    // Hash the Sig_structure
    let digest = Sha384::digest(&sig_structure_bytes);

    // Parse the public key
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| VerifyError::CoseVerify(format!("Invalid P-384 key: {}", e)))?;

    // Parse the signature (raw r||s format for COSE, not DER)
    let sig_bytes = &cose.signature;
    if sig_bytes.len() != 96 {
        return Err(VerifyError::CoseVerify(format!(
            "Invalid ES384 signature length: expected 96, got {}",
            sig_bytes.len()
        )));
    }

    // Convert raw r||s to DER format for the ecdsa crate
    let signature = Signature::from_slice(sig_bytes)
        .map_err(|e| VerifyError::CoseVerify(format!("Invalid signature: {}", e)))?;

    verifying_key
        .verify_prehash(&digest, &signature)
        .map_err(|e| VerifyError::CoseVerify(format!("Signature verification failed: {}", e)))
}
