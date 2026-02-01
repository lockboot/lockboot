// SPDX-License-Identifier: MIT OR Apache-2.0

//! TPM2 policy session operations
//!
//! Provides policy session management for TPM authorization flows.
//! Also includes utility functions for computing TPM object names.

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::{
    CommandBuffer, Tpm, TpmAlg, TpmCc, TpmSt,
    TPM_RS_PW, TPM_SE_POLICY, TPM_RH_NULL,
};

/// Result from ReadPublic
#[derive(Debug)]
pub struct ReadPublicResult {
    /// The raw TPMT_PUBLIC structure
    pub public_area: Vec<u8>,
    /// The object's name as computed by the TPM
    pub name: Vec<u8>,
}

/// Policy session operations
impl Tpm {
    /// Read the public area and name of an object
    ///
    /// This is useful for verifying that our name computation matches
    /// what the TPM actually has for an object.
    pub fn read_public(&mut self, object_handle: u32) -> Result<ReadPublicResult> {
        let command = CommandBuffer::new()
            .write_u32(object_handle)
            .finalize(TpmSt::NoSessions, TpmCc::ReadPublic);

        let mut resp = self.transmit(&command)?;

        // Parse response: outPublic (TPM2B_PUBLIC), name (TPM2B_NAME), qualifiedName (TPM2B_NAME)
        let public_area = resp.read_tpm2b()?;
        let name = resp.read_tpm2b()?;
        let _qualified_name = resp.read_tpm2b()?;

        Ok(ReadPublicResult {
            public_area,
            name,
        })
    }

    /// Start a policy session
    ///
    /// Creates a new policy session that can be used for policy-based authorization.
    /// The session must be flushed after use with `flush_context()`.
    pub fn start_policy_session(&mut self) -> Result<u32> {
        // TPM2_StartAuthSession
        // tpmKey = TPM_RH_NULL (no salt)
        // bind = TPM_RH_NULL (no bind)
        // nonceCaller = empty (TPM will generate)
        // encryptedSalt = empty
        // sessionType = TPM_SE_POLICY
        // symmetric = TPM_ALG_NULL
        // authHash = TPM_ALG_SHA256

        // Generate a random nonce (some TPMs require non-empty nonceCaller)
        // Use hash of current time as simple entropy source
        let nonce_data = Sha256::digest(
            &std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes()
        );
        let nonce_caller = &nonce_data[..16]; // Use 16 bytes

        let command = CommandBuffer::new()
            .write_u32(TPM_RH_NULL)         // tpmKey
            .write_u32(TPM_RH_NULL)         // bind
            .write_tpm2b(nonce_caller)      // nonceCaller (16 bytes)
            .write_u16(0)                   // encryptedSalt size (no salt)
            .write_u8(TPM_SE_POLICY)        // sessionType
            .write_u16(TpmAlg::Null as u16) // symmetric.algorithm = TPM_ALG_NULL
            .write_u16(TpmAlg::Sha256 as u16) // authHash = TPM_ALG_SHA256
            .finalize(TpmSt::NoSessions, TpmCc::StartAuthSession);

        let mut resp = self.transmit(&command)?;

        // Parse response: sessionHandle, nonceTPM
        let session_handle = resp.read_u32()?;
        let _nonce_tpm = resp.read_tpm2b()?; // We don't need the nonce for simple policy

        Ok(session_handle)
    }

    /// Execute PolicySecret command
    ///
    /// Satisfies a policy that requires PolicySecret(authHandle).
    /// For standard EK, authHandle should be TPM_RH_ENDORSEMENT.
    pub fn policy_secret(&mut self, policy_session: u32, auth_handle: u32) -> Result<()> {
        // TPM2_PolicySecret
        // authHandle: the entity providing authorization (TPM_RH_ENDORSEMENT)
        // policySession: the policy session to update
        // nonceTPM: empty
        // cpHashA: empty
        // policyRef: empty
        // expiration: 0

        let command = CommandBuffer::new()
            .write_u32(auth_handle)     // authHandle
            .write_u32(policy_session)  // policySession
            // Authorization for authHandle (password session, empty)
            .write_u32(9)               // authorizationSize
            .write_u32(TPM_RS_PW)
            .write_u16(0)               // nonce
            .write_u8(0)                // attributes
            .write_u16(0)               // password
            // Parameters
            .write_u16(0)               // nonceTPM size
            .write_u16(0)               // cpHashA size
            .write_u16(0)               // policyRef size
            .write_u32(0)               // expiration (INT32, 0 = no expiration)
            .finalize(TpmSt::Sessions, TpmCc::PolicySecret);

        let mut resp = self.transmit(&command)?;

        // Parse response - skip timeout and policyTicket
        let _parameter_size = resp.read_u32()?;
        // We don't need the timeout or ticket for our purposes

        Ok(())
    }

    /// Get the current policy digest from a policy session
    ///
    /// Useful for debugging to verify the policy matches expectations.
    pub fn policy_get_digest(&mut self, policy_session: u32) -> Result<Vec<u8>> {
        // TPM2_PolicyGetDigest
        // Input: policySession handle
        // Output: policyDigest (TPM2B_DIGEST)

        let command = CommandBuffer::new()
            .write_u32(policy_session)
            .finalize(TpmSt::NoSessions, TpmCc::PolicyGetDigest);

        let mut resp = self.transmit(&command)?;

        // Parse response: policyDigest (TPM2B_DIGEST)
        let digest = resp.read_tpm2b()?;

        Ok(digest.to_vec())
    }
}

/// Compute TPM object name from public key and authPolicy
///
/// name = nameAlg || H(TPMT_PUBLIC)
///
/// For ECC P-256 signing keys with PCR policy.
pub fn compute_ecc_p256_name(
    pubkey_x: &[u8],
    pubkey_y: &[u8],
    auth_policy: &[u8],
) -> Vec<u8> {
    // Build TPMT_PUBLIC for ECC P-256 signing key
    let mut public_area = Vec::new();

    // type: TPM_ALG_ECC (0x0023)
    public_area.extend_from_slice(&0x0023u16.to_be_bytes());
    // nameAlg: TPM_ALG_SHA256 (0x000B)
    public_area.extend_from_slice(&0x000Bu16.to_be_bytes());
    // objectAttributes: fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | decrypt | sign
    // bits: 1,4,5,6,17,18 = 0x00060072
    public_area.extend_from_slice(&0x00060072u32.to_be_bytes());
    // authPolicy (TPM2B_DIGEST)
    public_area.extend_from_slice(&(auth_policy.len() as u16).to_be_bytes());
    public_area.extend_from_slice(auth_policy);
    // parameters (TPMS_ECC_PARMS):
    //   symmetric: TPM_ALG_NULL (0x0010)
    public_area.extend_from_slice(&0x0010u16.to_be_bytes());
    //   scheme: TPM_ALG_NULL (0x0010)
    public_area.extend_from_slice(&0x0010u16.to_be_bytes());
    //   curveID: TPM_ECC_NIST_P256 (0x0003)
    public_area.extend_from_slice(&0x0003u16.to_be_bytes());
    //   kdf: TPM_ALG_NULL (0x0010)
    public_area.extend_from_slice(&0x0010u16.to_be_bytes());
    // unique (TPMS_ECC_POINT):
    //   x (TPM2B_ECC_PARAMETER)
    public_area.extend_from_slice(&(pubkey_x.len() as u16).to_be_bytes());
    public_area.extend_from_slice(pubkey_x);
    //   y (TPM2B_ECC_PARAMETER)
    public_area.extend_from_slice(&(pubkey_y.len() as u16).to_be_bytes());
    public_area.extend_from_slice(pubkey_y);

    // name = nameAlg || H(TPMT_PUBLIC)
    let mut name = Vec::new();
    name.extend_from_slice(&0x000Bu16.to_be_bytes()); // SHA256
    name.extend_from_slice(&Sha256::digest(&public_area));

    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_name_deterministic() {
        let x = [0x01u8; 32];
        let y = [0x02u8; 32];
        let policy = [0x03u8; 32];

        let name1 = compute_ecc_p256_name(&x, &y, &policy);
        let name2 = compute_ecc_p256_name(&x, &y, &policy);

        assert_eq!(name1, name2);
        // Name should be 2 (alg) + 32 (hash) = 34 bytes
        assert_eq!(name1.len(), 34);
        // Should start with SHA256 algorithm ID
        assert_eq!(&name1[0..2], &[0x00, 0x0B]);
    }

}
