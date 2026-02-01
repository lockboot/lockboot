// SPDX-License-Identifier: MIT OR Apache-2.0

//! EK and key operations
//!
//! Provides TPM key management operations including:
//! - Creating ECC primary keys (standard and custom templates)
//! - TCG-compliant standard EK creation
//! - Signing operations
//! - Key certification

use anyhow::{bail, Result};

use crate::{
    CertifyResult, CommandBuffer, EccPublicKey, ObjectAttributes, PrimaryKeyResult,
    ResponseBuffer, TpmAlg, TpmCc, TpmEccCurve, TpmSt, Tpm,
    TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RS_PW,
};

/// Standard EK authPolicy digest for SHA-256 (TCG EK Credential Profile 2.6)
/// This is PolicySecret(TPM_RH_ENDORSEMENT) with SHA-256
const STANDARD_EK_AUTH_POLICY: [u8; 32] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
    0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
    0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
    0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
];

/// EK and key operations extension trait
pub trait EkOps {
    /// Create a primary ECC P-256 signing key in the specified hierarchy (no policy)
    fn create_primary_ecc_key(&mut self, hierarchy: u32) -> Result<PrimaryKeyResult>;

    /// Create a primary ECC P-256 signing key with a specific authPolicy
    fn create_primary_ecc_key_with_policy(
        &mut self,
        hierarchy: u32,
        auth_policy: &[u8],
    ) -> Result<PrimaryKeyResult>;

    /// Create the TCG standard ECC P-256 Endorsement Key
    ///
    /// This creates an EK using the TCG standard template, which should produce
    /// a key whose public key matches the one in the EK certificate (if the certificate
    /// was issued for this TPM using the standard template).
    ///
    /// The standard EK is a decrypt-only key (cannot sign) with:
    /// - Attributes: fixedTPM, fixedParent, sensitiveDataOrigin, adminWithPolicy, restricted, decrypt
    /// - authPolicy: PolicySecret(TPM_RH_ENDORSEMENT)
    /// - Symmetric: AES-128-CFB
    /// - Curve: NIST P-256
    fn create_standard_ek(&mut self) -> Result<PrimaryKeyResult>;

    /// Sign data with a TPM key (returns DER-encoded ECDSA signature)
    fn sign(&mut self, key_handle: u32, digest: &[u8]) -> Result<Vec<u8>>;

    /// Certify a key using another key (e.g., certify signing key with EK)
    /// Returns (attestation_data, signature)
    fn certify(
        &mut self,
        object_handle: u32,
        sign_handle: u32,
        qualifying_data: &[u8],
    ) -> Result<CertifyResult>;
}

impl EkOps for Tpm {
    fn create_primary_ecc_key(&mut self, hierarchy: u32) -> Result<PrimaryKeyResult> {
        let public_area = build_ecc_public_area();

        let command = CommandBuffer::new()
            .write_u32(hierarchy)
            .write_auth_empty_pw()
            // inSensitive (TPM2B_SENSITIVE_CREATE)
            .write_u16(4)
            .write_u16(0) // userAuth size = 0
            .write_u16(0) // data size = 0
            // inPublic (TPM2B_PUBLIC)
            .write_tpm2b(&public_area)
            // outsideInfo (TPM2B_DATA) - empty
            .write_u16(0)
            // creationPCR (TPML_PCR_SELECTION) - empty
            .write_u32(0)
            .finalize(TpmSt::Sessions, TpmCc::CreatePrimary);
        let mut resp = self.transmit(&command)?;

        // Parse response
        let handle = resp.read_u32()?;
        let parameter_size = resp.read_u32()?;

        // Track where parameters start
        let param_start = resp.offset();

        // Read outPublic (TPM2B_PUBLIC)
        let public_size = resp.read_u16()? as usize;
        let public_data = resp.read_bytes(public_size)?;

        // Parse the public key from the public area
        let public_key = parse_ecc_public_key(public_data)?;

        // Skip remaining CreatePrimary output parameters
        let bytes_read = resp.offset() - param_start;
        if bytes_read < parameter_size as usize {
            let remaining = parameter_size as usize - bytes_read;
            resp.read_bytes(remaining)?;
        }

        // Verify we read exactly parameter_size bytes
        let final_bytes_read = resp.offset() - param_start;
        if final_bytes_read != parameter_size as usize {
            bail!(
                "Parameter size mismatch: TPM said {} bytes, we read {} bytes",
                parameter_size,
                final_bytes_read
            );
        }

        Ok(PrimaryKeyResult { handle, public_key })
    }

    fn create_standard_ek(&mut self) -> Result<PrimaryKeyResult> {
        let public_area = build_standard_ek_public_area();

        let command = CommandBuffer::new()
            .write_u32(TPM_RH_ENDORSEMENT)
            .write_auth_empty_pw()
            // inSensitive (TPM2B_SENSITIVE_CREATE)
            .write_u16(4)
            .write_u16(0) // userAuth size = 0
            .write_u16(0) // data size = 0
            // inPublic (TPM2B_PUBLIC)
            .write_tpm2b(&public_area)
            // outsideInfo (TPM2B_DATA) - empty
            .write_u16(0)
            // creationPCR (TPML_PCR_SELECTION) - empty
            .write_u32(0)
            .finalize(TpmSt::Sessions, TpmCc::CreatePrimary);
        let mut resp = self.transmit(&command)?;

        // Parse response
        let handle = resp.read_u32()?;
        let parameter_size = resp.read_u32()?;

        // Track where parameters start
        let param_start = resp.offset();

        // Read outPublic (TPM2B_PUBLIC)
        let public_size = resp.read_u16()? as usize;
        let public_data = resp.read_bytes(public_size)?;
        let public_key = parse_ecc_public_key(public_data)?;

        // Skip remaining CreatePrimary output parameters
        let bytes_read = resp.offset() - param_start;
        if bytes_read < parameter_size as usize {
            let remaining = parameter_size as usize - bytes_read;
            resp.read_bytes(remaining)?;
        }

        // Verify we read exactly parameter_size bytes
        let final_bytes_read = resp.offset() - param_start;
        if final_bytes_read != parameter_size as usize {
            bail!(
                "Parameter size mismatch: TPM said {} bytes, we read {} bytes",
                parameter_size,
                final_bytes_read
            );
        }

        Ok(PrimaryKeyResult { handle, public_key })
    }

    fn sign(&mut self, key_handle: u32, digest: &[u8]) -> Result<Vec<u8>> {
        if digest.len() != 32 {
            bail!("Digest must be 32 bytes for SHA-256");
        }

        let command = CommandBuffer::new()
            .write_u32(key_handle)
            .write_auth_empty_pw()
            // digest (TPM2B_DIGEST)
            .write_tpm2b(digest)
            // inScheme (TPMT_SIG_SCHEME) - ECDSA with SHA256
            .write_u16(TpmAlg::EcDsa as u16)
            .write_u16(TpmAlg::Sha256 as u16)
            // validation (TPMT_TK_HASHCHECK) - NULL ticket
            .write_u16(0x8024) // TPM_ST_HASHCHECK
            .write_u32(TPM_RH_NULL)
            .write_u16(0) // digest size = 0
            .finalize(TpmSt::Sessions, TpmCc::Sign);
        let mut resp = self.transmit(&command)?;

        // Parse response
        let parameter_size = resp.read_u32()?;
        let param_start = resp.offset();

        // TPMT_SIGNATURE
        let sig_alg = resp.read_u16()?;
        if sig_alg != TpmAlg::EcDsa as u16 {
            bail!("Unexpected signature algorithm: 0x{:04X}", sig_alg);
        }

        let hash_alg = resp.read_u16()?;
        if hash_alg != TpmAlg::Sha256 as u16 {
            bail!("Unexpected hash algorithm: 0x{:04X}", hash_alg);
        }

        // TPMS_SIGNATURE_ECC
        let r = resp.read_tpm2b()?;
        let s = resp.read_tpm2b()?;

        // Verify we read exactly parameter_size bytes
        let bytes_read = resp.offset() - param_start;
        if bytes_read != parameter_size as usize {
            bail!(
                "Parameter size mismatch in Sign: TPM said {} bytes, we read {} bytes",
                parameter_size,
                bytes_read
            );
        }

        // Convert to DER-encoded signature
        Ok(encode_ecdsa_der_signature(&r, &s))
    }

    fn certify(
        &mut self,
        object_handle: u32,
        sign_handle: u32,
        qualifying_data: &[u8],
    ) -> Result<CertifyResult> {
        let command = CommandBuffer::new()
            .write_u32(object_handle)
            .write_u32(sign_handle)
            // Authorization area - two sessions (one for each handle)
            // Total auth size = 2 * 9 = 18 bytes
            .write_u32(18)
            // Auth for objectHandle (password session, empty password)
            .write_u32(TPM_RS_PW)
            .write_u16(0) // nonce
            .write_u8(0) // attributes
            .write_u16(0) // password
            // Auth for signHandle (password session, empty password)
            .write_u32(TPM_RS_PW)
            .write_u16(0) // nonce
            .write_u8(0) // attributes
            .write_u16(0) // password
            // qualifyingData (TPM2B_DATA)
            .write_tpm2b(qualifying_data)
            // inScheme (TPMT_SIG_SCHEME) - ECDSA with SHA256
            .write_u16(TpmAlg::EcDsa as u16)
            .write_u16(TpmAlg::Sha256 as u16)
            .finalize(TpmSt::Sessions, TpmCc::Certify);
        let mut resp = self.transmit(&command)?;

        // Parse response
        let parameter_size = resp.read_u32()?;
        let param_start = resp.offset();

        // certifyInfo (TPM2B_ATTEST)
        let attest_data = resp.read_tpm2b()?;

        // signature (TPMT_SIGNATURE)
        let sig_alg = resp.read_u16()?;
        if sig_alg != TpmAlg::EcDsa as u16 {
            bail!("Unexpected signature algorithm: 0x{:04X}", sig_alg);
        }

        let hash_alg = resp.read_u16()?;
        if hash_alg != TpmAlg::Sha256 as u16 {
            bail!("Unexpected hash algorithm: 0x{:04X}", hash_alg);
        }

        // TPMS_SIGNATURE_ECC
        let r = resp.read_tpm2b()?;
        let s = resp.read_tpm2b()?;

        // Verify we read exactly parameter_size bytes
        let bytes_read = resp.offset() - param_start;
        if bytes_read != parameter_size as usize {
            bail!(
                "Parameter size mismatch in Certify: TPM said {} bytes, we read {} bytes",
                parameter_size,
                bytes_read
            );
        }

        let signature = encode_ecdsa_der_signature(&r, &s);

        Ok(CertifyResult {
            attest_data: attest_data.to_vec(),
            signature,
        })
    }

    fn create_primary_ecc_key_with_policy(
        &mut self,
        hierarchy: u32,
        auth_policy: &[u8],
    ) -> Result<PrimaryKeyResult> {
        let public_area = build_ecc_public_area_with_policy(auth_policy);

        let command = CommandBuffer::new()
            .write_u32(hierarchy)
            .write_auth_empty_pw()
            // inSensitive (TPM2B_SENSITIVE_CREATE)
            .write_u16(4)
            .write_u16(0) // userAuth size = 0
            .write_u16(0) // data size = 0
            // inPublic (TPM2B_PUBLIC) - with authPolicy
            .write_tpm2b(&public_area)
            // outsideInfo (TPM2B_DATA) - empty
            .write_u16(0)
            // creationPCR (TPML_PCR_SELECTION) - empty
            .write_u32(0)
            .finalize(TpmSt::Sessions, TpmCc::CreatePrimary);
        let mut resp = self.transmit(&command)?;

        // Parse response
        let handle = resp.read_u32()?;
        let parameter_size = resp.read_u32()?;

        // Track where parameters start
        let param_start = resp.offset();

        // Read outPublic (TPM2B_PUBLIC)
        let public_size = resp.read_u16()? as usize;
        let public_data = resp.read_bytes(public_size)?;
        let public_key = parse_ecc_public_key(public_data)?;

        // Skip remaining CreatePrimary output parameters
        let bytes_read = resp.offset() - param_start;
        if bytes_read < parameter_size as usize {
            let remaining = parameter_size as usize - bytes_read;
            resp.read_bytes(remaining)?;
        }

        // Verify we read exactly parameter_size bytes
        let final_bytes_read = resp.offset() - param_start;
        if final_bytes_read != parameter_size as usize {
            bail!(
                "Parameter size mismatch: TPM said {} bytes, we read {} bytes",
                parameter_size,
                final_bytes_read
            );
        }

        Ok(PrimaryKeyResult { handle, public_key })
    }
}

/// Build a TPM2B_PUBLIC structure for an ECC P-256 signing key
fn build_ecc_public_area() -> Vec<u8> {
    let attrs = ObjectAttributes::new()
        .fixed_tpm()
        .fixed_parent()
        .sensitive_data_origin()
        .user_with_auth()
        .decrypt()
        .sign_encrypt();

    CommandBuffer::new()
        // TPMT_PUBLIC
        .write_u16(TpmAlg::Ecc as u16) // type
        .write_u16(TpmAlg::Sha256 as u16) // nameAlg
        .write_u32(attrs.value()) // objectAttributes
        .write_u16(0) // authPolicy (empty)
        // parameters (TPMS_ECC_PARMS)
        .write_u16(TpmAlg::Null as u16) // symmetric
        .write_u16(TpmAlg::Null as u16) // scheme
        .write_u16(TpmEccCurve::NistP256 as u16) // curveID
        .write_u16(TpmAlg::Null as u16) // kdf
        // unique (TPMS_ECC_POINT) - empty
        .write_u16(0) // x size
        .write_u16(0) // y size
        .into_vec()
}

/// Build a TPM2B_PUBLIC structure for an ECC P-256 signing key with authPolicy
fn build_ecc_public_area_with_policy(auth_policy: &[u8]) -> Vec<u8> {
    let attrs = ObjectAttributes::new()
        .fixed_tpm()
        .fixed_parent()
        .sensitive_data_origin()
        .user_with_auth()
        .decrypt()
        .sign_encrypt();

    CommandBuffer::new()
        // TPMT_PUBLIC
        .write_u16(TpmAlg::Ecc as u16) // type
        .write_u16(TpmAlg::Sha256 as u16) // nameAlg
        .write_u32(attrs.value()) // objectAttributes
        .write_tpm2b(auth_policy) // authPolicy
        // parameters (TPMS_ECC_PARMS)
        .write_u16(TpmAlg::Null as u16) // symmetric
        .write_u16(TpmAlg::Null as u16) // scheme
        .write_u16(TpmEccCurve::NistP256 as u16) // curveID
        .write_u16(TpmAlg::Null as u16) // kdf
        // unique (TPMS_ECC_POINT) - empty
        .write_u16(0) // x size
        .write_u16(0) // y size
        .into_vec()
}

/// Build a TPM2B_PUBLIC structure for the TCG standard ECC P-256 EK
///
/// Per TCG EK Credential Profile 2.6, the standard EK template (Template L-2) has:
/// - Object attributes: 0x000300b2 (fixedTPM, fixedParent, sensitiveDataOrigin,
///   adminWithPolicy, restricted, decrypt)
/// - authPolicy: PolicySecret(TPM_RH_ENDORSEMENT)
/// - Symmetric: AES-128-CFB
/// - Curve: NIST P-256
/// - Unique: x = 32 zero bytes, y = 32 zero bytes
fn build_standard_ek_public_area() -> Vec<u8> {
    let attrs = ObjectAttributes::new()
        .fixed_tpm()
        .fixed_parent()
        .sensitive_data_origin()
        .admin_with_policy()
        .restricted()
        .decrypt();

    // Per TCG EK Credential Profile, unique field must be 32 zero bytes for x and y
    let zero_32 = [0u8; 32];

    CommandBuffer::new()
        // TPMT_PUBLIC
        .write_u16(TpmAlg::Ecc as u16) // type
        .write_u16(TpmAlg::Sha256 as u16) // nameAlg
        .write_u32(attrs.value()) // objectAttributes
        .write_tpm2b(&STANDARD_EK_AUTH_POLICY) // authPolicy
        // parameters (TPMS_ECC_PARMS)
        // symmetric (TPMT_SYM_DEF_OBJECT) - AES-128-CFB
        .write_u16(TpmAlg::Aes as u16)
        .write_u16(128) // keyBits
        .write_u16(TpmAlg::Cfb as u16) // mode
        .write_u16(TpmAlg::Null as u16) // scheme (decrypt-only, no signing)
        .write_u16(TpmEccCurve::NistP256 as u16) // curveID
        .write_u16(TpmAlg::Null as u16) // kdf
        // unique (TPMS_ECC_POINT) - 32 zero bytes each per TCG template
        .write_tpm2b(&zero_32) // x
        .write_tpm2b(&zero_32) // y
        .into_vec()
}

/// Parse ECC public key from TPMT_PUBLIC structure
pub(crate) fn parse_ecc_public_key(data: &[u8]) -> Result<EccPublicKey> {
    let mut resp = ResponseBuffer::new(data.to_vec());

    // Parse TPMT_PUBLIC structure
    let key_type = resp.read_u16()?;
    let name_alg = resp.read_u16()?;
    let object_attributes = resp.read_u32()?;
    let auth_policy = resp.read_tpm2b()?;

    // Parse parameters (TPMS_ECC_PARMS for ECC keys)
    let symmetric = resp.read_u16()?;

    // If symmetric is not NULL, read symmetric details
    if symmetric != TpmAlg::Null as u16 {
        let _key_bits = resp.read_u16()?;
        let _mode = resp.read_u16()?;
    }

    let scheme = resp.read_u16()?;

    // Only read scheme details if scheme is not NULL
    if scheme != TpmAlg::Null as u16 {
        let _scheme_detail = resp.read_u16()?;
    }

    let curve_id = resp.read_u16()?;
    let kdf = resp.read_u16()?;

    // Read unique (TPMS_ECC_POINT)
    let x = resp.read_tpm2b()?;
    let y = resp.read_tpm2b()?;

    Ok(EccPublicKey {
        key_type,
        name_alg,
        object_attributes,
        auth_policy,
        symmetric,
        scheme,
        curve_id,
        kdf,
        x,
        y,
    })
}

/// Encode ECDSA signature as DER
pub(crate) fn encode_ecdsa_der_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    fn encode_integer(value: &[u8]) -> Vec<u8> {
        let mut result = vec![0x02]; // INTEGER tag

        // Remove leading zeros
        let trimmed: Vec<u8> = value.iter().skip_while(|&&b| b == 0).copied().collect();

        let bytes = if trimmed.is_empty() {
            vec![0x00]
        } else if trimmed[0] & 0x80 != 0 {
            // Add padding byte if high bit is set
            let mut v = vec![0x00];
            v.extend_from_slice(&trimmed);
            v
        } else {
            trimmed
        };

        result.push(bytes.len() as u8);
        result.extend_from_slice(&bytes);
        result
    }

    let r_encoded = encode_integer(r);
    let s_encoded = encode_integer(s);

    let mut signature = vec![0x30]; // SEQUENCE tag
    let content_len = r_encoded.len() + s_encoded.len();
    signature.push(content_len as u8);
    signature.extend_from_slice(&r_encoded);
    signature.extend_from_slice(&s_encoded);
    signature
}
