// SPDX-License-Identifier: MIT OR Apache-2.0

//! AWS Nitro Secure Module (NSM) API - Clean Implementation
//!
//! Single-approach implementation based on TPM 2.0 spec and AWS trace analysis.
//! No "try everything" - either works correctly or fails with clear diagnostics.

use crate::{Tpm, TpmSt, CommandBuffer, TPM_ALG_SHA256};
use crate::nv::{NV_INDEX_USER_START, NV_INDEX_USER_END, NvOps, TPM2_PT_NV_BUFFER_MAX};
use crate::nv::{TPMA_NV_AUTHWRITE, TPMA_NV_AUTHREAD};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// NSM Request types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Attestation {
        user_data: Option<Vec<u8>>,
        nonce: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
    },
}

/// Digest algorithm used by NSM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Digest {
    SHA256,
    SHA384,
    SHA512,
}

/// NSM Response types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Response {
    Attestation {
        #[serde(rename = "document", with = "serde_bytes")]
        document: Vec<u8>,
    },
    Error(ErrorCode),
}

/// NSM Error codes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorCode {
    InvalidArgument,
    InvalidIndex,
    InvalidResponse,
    ReadOnlyIndex,
    InvalidOperation,
    BufferTooSmall,
    InputTooLarge,
    InternalError,
}

impl Request {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_cbor::to_vec(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize NSM request: {}", e))
    }
}

impl Response {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        use serde::Deserialize;
        let mut deserializer = serde_cbor::Deserializer::from_slice(data);
        let response = Response::deserialize(&mut deserializer)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize NSM response: {}", e))?;
        // Don't check for trailing data - NV index has 0xFF padding
        Ok(response)
    }
}

/// AWS Nitro TPM vendor-specific command for NSM requests
pub const TPM2_VENDOR_AWS_NSM_REQUEST: u32 = 0x20000001;

/// Extension trait for AWS Nitro Security Module (NSM) operations
pub trait NsmOps {
    /// Request an attestation document from NSM
    ///
    /// This requests an attestation document from the AWS Nitro Secure Module.
    /// The attestation document is a signed CBOR structure that includes:
    /// - PCR values from the TPM
    /// - Optional user data (up to 512 bytes)
    /// - Optional nonce (up to 512 bytes)
    /// - Optional public key (DER-encoded)
    ///
    /// # Arguments
    /// * `user_data` - Optional user-provided data to include in attestation
    /// * `nonce` - Optional nonce/challenge for freshness
    /// * `public_key` - Optional public key to include in attestation
    ///
    /// # Returns
    /// The attestation document as a CBOR-encoded byte vector
    fn nsm_attest(
        &mut self,
        user_data: Option<Vec<u8>>,
        nonce: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
    ) -> Result<Vec<u8>>;
}

/// Execute AWS NSM vendor command with password authentication
fn nsm_vendor_command(
    tpm: &mut Tpm,
    nv_index: u32
) -> Result<()> {
    // Use password session with empty password
    let command = CommandBuffer::new()
        .write_u32(nv_index)                    // nvAuth
        .write_u32(nv_index)                    // nvIndex
        .write_auth_empty_pw()
        .finalize_vendor(TpmSt::Sessions, TPM2_VENDOR_AWS_NSM_REQUEST);
    tpm.transmit(&command)?;
    Ok(())
}

/// Execute AWS Nitro Security Module (NSM) request
fn nsm_raw_request(tpm: &mut Tpm, request_data: &[u8]) -> Result<Vec<u8>> {
    // Query TPM's maximum NV buffer size (for writes)
    let max_nv_bufsz = tpm.get_property(TPM2_PT_NV_BUFFER_MAX)?;
    if request_data.len() > max_nv_bufsz as usize {
        bail!("NSM request too large: {} bytes (TPM max buffer: {} bytes)",
            request_data.len(), max_nv_bufsz);
    }

    // Find a free NV index
    let nv_index = tpm.nv_find_free_index(NV_INDEX_USER_START, NV_INDEX_USER_END)?;    

    // Use a guard to ensure cleanup
    struct NvGuard<'a> {
        tpm: &'a mut Tpm,
        nv_index: u32,
    }

    impl Drop for NvGuard<'_> {
        fn drop(&mut self) {
            let _ = self.tpm.nv_undefine_space(self.nv_index);
        }
    }

    // The NV space must be large enough to accommodate max(len(req),len(resp))
    tpm.nv_define_space(nv_index, 8192, TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD, TPM_ALG_SHA256)?;

    let guard = NvGuard { tpm, nv_index };

    // Write request data        
    guard.tpm.nv_write(nv_index, request_data)?;
    nsm_vendor_command(guard.tpm, nv_index)?;

    // Read response
    let response = guard.tpm.nv_read(nv_index)?;
    drop(guard);
    Ok(response)
}

impl NsmOps for Tpm {
    /// Request an attestation document from NSM
    fn nsm_attest(
        &mut self,
        user_data: Option<Vec<u8>>,
        nonce: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let request = Request::Attestation {
            user_data,
            nonce,
            public_key,
        };
        let request_bytes = request.to_bytes()?;

        let response_bytes = nsm_raw_request(self, &request_bytes)?;

        let response = Response::from_bytes(&response_bytes)?;

        match response {
            Response::Attestation{document} => Ok(document),
            Response::Error(err) => bail!("NSM returned error: {:?}", err),
        }
    }
}
