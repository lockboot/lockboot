// SPDX-License-Identifier: MIT OR Apache-2.0

//! TPM attestation functionality
//!
//! Provides high-level attestation operations including:
//! - Retrieving EK certificates from NV RAM
//! - Creating and certifying attestation keys (AK)
//! - Reading PCR values
//! - Generating attestation documents

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, BTreeMap};

use crate::{Tpm, EkOps, NvOps, PcrOps, NsmOps, TPM_RH_OWNER};
use crate::{NV_INDEX_RSA_2048_EK_CERT, NV_INDEX_ECC_P256_EK_CERT, NV_INDEX_ECC_P384_EK_CERT};
use crate::credential::compute_ecc_p256_name;

/// Complete attestation output containing all TPM attestation data
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationOutput {
    pub ek_certificates: EkCertificates,
    pub pcrs: HashMap<String, BTreeMap<u8, String>>,
    pub ek_public_keys: HashMap<String, EkPublicKey>,
    pub signing_key_public_keys: HashMap<String, EkPublicKey>,
    pub attestation: AttestationContainer,
}

/// Endorsement Key certificates in PEM format
#[derive(Debug, Serialize, Deserialize)]
pub struct EkCertificates {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsa_2048: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecc_p256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecc_p384: Option<String>,
}

/// ECC public key coordinates
#[derive(Debug, Serialize, Deserialize)]
pub struct EkPublicKey {
    pub x: String,
    pub y: String,
}

/// Container for both TPM and optional Nitro attestations
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationContainer {
    pub tpm: HashMap<String, AttestationData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nitro: Option<NitroAttestationData>,
}

/// TPM attestation data (certify response with NIZK proof)
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationData {
    /// The nonce/challenge provided to the attestation (hex-encoded)
    /// This is duplicated from attest_data.extraData for easy access.
    /// Verification MUST check this matches the nonce in attest_data.
    pub nonce: String,
    /// TPM2B_ATTEST structure from TPM2_Certify (hex-encoded)
    pub attest_data: String,
    /// ECDSA signature over attest_data (DER, hex-encoded)
    pub signature: String,
}

/// Nitro Enclave attestation data
#[derive(Debug, Serialize, Deserialize)]
pub struct NitroAttestationData {
    pub public_key: String,
    pub nonce: String,
    pub document: String,
}

/// Convert DER-encoded data to PEM format
pub fn der_to_pem(der: &[u8], label: &str) -> String {
    let base64_encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in base64_encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}

/// Generate a complete TPM attestation document
///
/// This function:
/// 1. Retrieves EK certificates from NV RAM
/// 2. Creates the TCG standard EK (matches certificate public key)
/// 3. Reads all PCRs from all banks
/// 4. Creates a signing key bound to current PCR values
/// 5. Has the signing key sign the nonce (proves PCR state + freshness)
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

    // Step 2: Create TCG standard EK (public key should match certificate)
    // Note: Standard EK is decrypt-only, cannot sign. We use it only for
    // identity verification (comparing public key with certificate).
    let ek = tpm.create_standard_ek()
        .context("Failed to create standard EK - endorsement hierarchy may require authentication")?;

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

    // Step 4: Get SHA-256 PCR values from what we already read
    // Use values from all_pcrs (which reads one at a time correctly)
    let sha256_pcr_values: Vec<(u8, Vec<u8>)> = all_pcrs.iter()
        .filter(|(_, alg, _)| *alg == crate::TpmAlg::Sha256)
        .map(|(idx, _, val)| (*idx, val.clone()))
        .collect();

    if sha256_pcr_values.is_empty() {
        return Err(anyhow!("No SHA-256 PCRs allocated on this TPM"));
    }

    // Compute policy from SHA-256 PCR values
    let auth_policy = Tpm::calculate_pcr_policy_digest(&sha256_pcr_values)?;

    // Create signing key (AK) bound to this policy
    let signing_key = tpm.create_primary_ecc_key_with_policy(TPM_RH_OWNER, &auth_policy)?;

    let mut signing_key_public_keys = HashMap::new();
    signing_key_public_keys.insert("ecc_p256".to_string(), EkPublicKey {
        x: hex::encode(&signing_key.public_key.x),
        y: hex::encode(&signing_key.public_key.y),
    });

    // Compute AK name (used for PCR policy verification)
    let _ak_name = compute_ecc_p256_name(
        &signing_key.public_key.x,
        &signing_key.public_key.y,
        &auth_policy,
    );

    // Step 6: AK self-certifies via TPM2_Certify
    // This produces TPM2B_ATTEST containing the AK's name (which includes authPolicy)
    let cert_result = tpm.certify(
        signing_key.handle,  // object to certify (AK itself)
        signing_key.handle,  // signing key (AK)
        nonce,               // qualifying data (becomes extraData in TPM2B_ATTEST)
    )?;

    let attestation_data = AttestationData {
        nonce: hex::encode(nonce),
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
