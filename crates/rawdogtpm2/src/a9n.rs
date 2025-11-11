// SPDX-License-Identifier: MIT OR Apache-2.0

//! TPM attestation functionality
//!
//! Provides high-level attestation operations including:
//! - Retrieving EK certificates from NV RAM
//! - Creating and certifying attestation keys
//! - Reading PCR values
//! - Generating attestation documents

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Serialize;
use std::collections::{HashMap, BTreeMap};

use crate::{Tpm, NvOps, PcrOps, NsmOps, TPM_RH_ENDORSEMENT, TPM_RH_OWNER};
use crate::{NV_INDEX_RSA_2048_EK_CERT, NV_INDEX_ECC_P256_EK_CERT, NV_INDEX_ECC_P384_EK_CERT};

/// Complete attestation output containing all TPM attestation data
#[derive(Debug, Serialize)]
pub struct AttestationOutput {
    pub ek_certificates: EkCertificates,
    pub pcrs: HashMap<String, BTreeMap<u8, String>>,
    pub ek_public_keys: HashMap<String, EkPublicKey>,
    pub signing_key_public_keys: HashMap<String, EkPublicKey>,
    pub attestation: AttestationContainer,
}

/// Endorsement Key certificates in PEM format
#[derive(Debug, Serialize)]
pub struct EkCertificates {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsa_2048: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecc_p256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecc_p384: Option<String>,
}

/// ECC public key coordinates
#[derive(Debug, Serialize)]
pub struct EkPublicKey {
    pub x: String,
    pub y: String,
}

/// Container for both TPM and optional Nitro attestations
#[derive(Debug, Serialize)]
pub struct AttestationContainer {
    pub tpm: HashMap<String, AttestationData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nitro: Option<NitroAttestationData>,
}

/// TPM attestation data (certify response)
#[derive(Debug, Serialize)]
pub struct AttestationData {
    pub attest_data: String,
    pub signature: String,
}

/// Nitro Enclave attestation data
#[derive(Debug, Serialize)]
pub struct NitroAttestationData {
    pub public_key: String,
    pub nonce: String,
    pub document: String,
}

/// Convert DER-encoded certificate to PEM format
fn der_to_pem(der: &[u8], label: &str) -> String {
    let base64_encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in base64_encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----", label));
    pem
}

/// Generate a complete TPM attestation document
///
/// This function:
/// 1. Retrieves EK certificates from NV RAM
/// 2. Creates an EK and extracts its public key
/// 3. Reads all PCRs from all banks
/// 4. Creates a signing key bound to current PCR values
/// 5. Certifies the signing key with the EK
/// 6. If on AWS Nitro, generates a Nitro attestation document
///
/// # Arguments
/// * `nonce` - User-provided nonce/challenge to include in attestation
///
/// # Returns
/// JSON-encoded attestation document containing all attestation data
pub fn attest(nonce: &[u8]) -> Result<String> {
    let mut tpm = Tpm::open_direct()?;

    // Step 1: Retrieve EK certificates from NV RAM
    let mut ek_certs = EkCertificates {
        rsa_2048: None,
        ecc_p256: None,
        ecc_p384: None,
    };

    // Try to read RSA EK cert
    if let Ok(cert) = tpm.nv_read(NV_INDEX_RSA_2048_EK_CERT) {
        if cert.starts_with(&[0x30, 0x82]) {
            ek_certs.rsa_2048 = Some(der_to_pem(&cert, "CERTIFICATE"));
        }
    }

    // Try to read ECC P-256 EK cert
    if let Ok(cert) = tpm.nv_read(NV_INDEX_ECC_P256_EK_CERT) {
        if cert.starts_with(&[0x30, 0x82]) {
            ek_certs.ecc_p256 = Some(der_to_pem(&cert, "CERTIFICATE"));
        }
    }

    // Try to read ECC P-384 EK cert
    if let Ok(cert) = tpm.nv_read(NV_INDEX_ECC_P384_EK_CERT) {
        if cert.starts_with(&[0x30, 0x82]) {
            ek_certs.ecc_p384 = Some(der_to_pem(&cert, "CERTIFICATE"));
        }
    }

    // Step 2: Create/access EK to get public key (P256 for now)
    let ek = tpm.create_primary_ecc_key(TPM_RH_ENDORSEMENT)
        .context("Failed to create EK - endorsement hierarchy may require authentication")?;

    let mut ek_public_keys = HashMap::new();
    ek_public_keys.insert("ecc_p256".to_string(), EkPublicKey {
        x: hex::encode(&ek.public_key.x),
        y: hex::encode(&ek.public_key.y),
    });

    // Step 3: Read all allocated PCRs from all banks
    let all_pcrs = tpm.read_all_allocated_pcrs()?;

    // Organize PCRs by algorithm (BTreeMap keeps PCRs sorted numerically)
    let mut pcrs_by_alg: HashMap<String, BTreeMap<u8, String>> = HashMap::new();
    for (index, alg, value) in &all_pcrs {
        let alg_name = alg.name().to_string();
        let pcr_map = pcrs_by_alg.entry(alg_name).or_insert_with(BTreeMap::new);
        pcr_map.insert(*index, hex::encode(value));
    }

    // Step 4: Get all unique PCR indices for policy
    let mut pcr_indices: Vec<u8> = all_pcrs.iter().map(|(idx, _, _)| *idx).collect();
    pcr_indices.sort_unstable();
    pcr_indices.dedup();

    // Use the algorithm from the first PCR (typically SHA-256)
    let bank_alg = all_pcrs.first()
        .map(|(_, alg, _)| *alg)
        .ok_or_else(|| anyhow!("No PCRs found"))?;

    let signing_key = tpm.create_primary_ecc_key_with_pcr_policy(TPM_RH_OWNER, &pcr_indices, bank_alg)?;

    let mut signing_key_public_keys = HashMap::new();
    signing_key_public_keys.insert("ecc_p256".to_string(), EkPublicKey {
        x: hex::encode(&signing_key.public_key.x),
        y: hex::encode(&signing_key.public_key.y),
    });

    // Step 5: Certify the signing key with the EK
    let cert_result = tpm.certify(signing_key.handle, ek.handle, nonce)?;

    let attestation_data = AttestationData {
        attest_data: hex::encode(&cert_result.attest_data),
        signature: hex::encode(&cert_result.signature),
    };

    let mut tpm_attestations = HashMap::new();
    tpm_attestations.insert("ecc_p256".to_string(), attestation_data);

    // Check if this is a Nitro TPM and get Nitro attestation if available
    let nitro_attestation = if tpm.is_nitro_tpm()? {
        // Encode signing key public key in SECG format (0x04 || X || Y)
        let mut public_key_secg = Vec::with_capacity(1 + signing_key.public_key.x.len() + signing_key.public_key.y.len());
        public_key_secg.push(0x04); // Uncompressed point indicator
        public_key_secg.extend_from_slice(&signing_key.public_key.x);
        public_key_secg.extend_from_slice(&signing_key.public_key.y);

        match tpm.nsm_attest(
            None, // user_data
            Some(nonce.to_vec()), // nonce
            Some(public_key_secg.clone()) // public_key
        ) {
            Ok(document) => {
                Some(NitroAttestationData {
                    public_key: hex::encode(&public_key_secg),
                    nonce: hex::encode(nonce),
                    document: hex::encode(&document),
                })
            }
            Err(_e) => {
                None
            }
        }
    }
    else {
        None
    };

    let attestation = AttestationContainer {
        tpm: tpm_attestations,
        nitro: nitro_attestation,
    };

    // Cleanup TPM handles
    tpm.flush_context(signing_key.handle)?;
    tpm.flush_context(ek.handle)?;

    // Step 6: Build and output JSON
    let output = AttestationOutput {
        ek_certificates: ek_certs,
        pcrs: pcrs_by_alg,
        ek_public_keys,
        signing_key_public_keys,
        attestation,
    };

    let json = serde_json::to_string_pretty(&output)?;

    Ok(json)
}
