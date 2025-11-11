// SPDX-License-Identifier: MIT OR Apache-2.0

//! NV (Non-Volatile) RAM operations
//!
//! Extension trait providing NV-related functionality for TPM.

use crate::{Tpm, TpmCc, TpmSt, CommandBuffer};
use crate::{TPM_RH_OWNER, TPM_CAP_HANDLES};
use anyhow::{Result, bail};

/// TPM handle types
pub const TPM_HT_NV_INDEX: u32 = 0x01000000;

/// TPM property identifiers
pub const TPM2_PT_NV_BUFFER_MAX: u32 = 0x0000010D; // Max NV buffer size (different from index max)
pub const TPM2_PT_NV_INDEX_MAX: u32 = 0x00000112;  // Max NV index data size

/// NV index range for user-defined indices (0x01800000 - 0x01BFFFFF)
pub const NV_INDEX_USER_START: u32 = 0x01800000;
pub const NV_INDEX_USER_END: u32 = 0x01BFFFFF;

/// NV attribute bits
pub const TPMA_NV_PPWRITE: u32 = 1 << 0;       // Platform hierarchy can write
pub const TPMA_NV_OWNERWRITE: u32 = 1 << 1;    // Owner hierarchy can write
pub const TPMA_NV_AUTHWRITE: u32 = 1 << 2;     // Authorizations to write are allowed
pub const TPMA_NV_POLICYWRITE: u32 = 1 << 3;   // Policy can be used to authorize write
pub const TPMA_NV_PPREAD: u32 = 1 << 16;       // Platform hierarchy can read
pub const TPMA_NV_OWNERREAD: u32 = 1 << 17;    // Owner hierarchy can read
pub const TPMA_NV_AUTHREAD: u32 = 1 << 18;     // Authorizations to read are allowed
pub const TPMA_NV_POLICYREAD: u32 = 1 << 19;   // Policy can be used to authorize read
pub const TPMA_NV_NO_DA: u32 = 1 << 25;        // Authorization failures do not affect DA logic
pub const TPMA_NV_ORDERLY: u32 = 1 << 26;      // NV Index state is only required to be saved on orderly shutdown

/// NV index public information
#[derive(Debug)]
pub struct NvPublicInfo {
    pub nv_index: u32,
    pub name_alg: u16,
    pub attributes: u32,
    pub auth_policy: Vec<u8>,
    pub data_size: u16,
    pub name: Vec<u8>,
}

/// Extension trait for NV RAM operations
pub trait NvOps {
    /// Get list of defined NV indices
    fn nv_indices(&mut self) -> Result<Vec<u32>>;

    /// Get NV index public information
    fn nv_readpublic(&mut self, nv_index: u32) -> Result<NvPublicInfo>;

    /// Read a raw block from NV RAM (low-level, no authentication)
    fn nv_read_raw_block(&mut self, nv_index: u32, size: u16, offset: u16) -> Result<Vec<u8>>;

    /// Read data from NV RAM (handles multi-block reads automatically)
    fn nv_read(&mut self, nv_index: u32) -> Result<Vec<u8>>;

    /// Define an NV space with the given attributes and authorization value
    fn nv_define_space(
        &mut self,
        nv_index: u32,
        data_size: u16,
        attributes: u32,
        name_alg: u16
    ) -> Result<()>;

    /// Write data to NV RAM
    fn nv_write(
        &mut self,
        nv_index: u32,
        data: &[u8]
    ) -> Result<()>;

    /// Undefine (delete) an NV space
    fn nv_undefine_space(&mut self, nv_index: u32) -> Result<()>;

    /// Find a free NV index in the specified range
    fn nv_find_free_index(&mut self, start: u32, end: u32) -> Result<u32>;
}

impl NvOps for Tpm {
    /// Get list of defined NV indices
    fn nv_indices(&mut self) -> Result<Vec<u32>> {
        let mut all_handles = Vec::new();
        let mut more_data = true;
        let mut property = TPM_HT_NV_INDEX; // Start from first NV index

        while more_data {
            let (has_more, mut resp) = self.get_capability(TPM_CAP_HANDLES, property, 64)?;
            more_data = has_more;

            // Parse capability-specific data: TPML_HANDLE
            let count = resp.read_u32()?;

            for _ in 0..count {
                let handle = resp.read_u32()?;
                all_handles.push(handle);
                property = handle + 1; // Next query starts after this handle
            }

            // If we got no handles, stop even if more_data is set
            if count == 0 {
                break;
            }
        }

        Ok(all_handles)
    }

    /// Get information about an NV index (size, attributes, policy)
    fn nv_readpublic(&mut self, nv_index: u32) -> Result<NvPublicInfo> {
        let command = CommandBuffer::new()
            .write_u32(nv_index) // nvIndex
            .finalize(TpmSt::NoSessions, TpmCc::NvReadPublic);
        let mut resp = self.transmit(&command)?;

        // Parse response
        // nvPublic (TPM2B_NV_PUBLIC)
        let _nv_public_size = resp.read_u16()? as usize;

        // TPMS_NV_PUBLIC structure
        let nv_index_ret = resp.read_u32()?;
        let name_alg = resp.read_u16()?;
        let attributes = resp.read_u32()?;

        // authPolicy (TPM2B_DIGEST)
        let auth_policy = resp.read_tpm2b()?;

        // dataSize
        let data_size = resp.read_u16()?;

        // nvName (TPM2B_NAME)
        let name = resp.read_tpm2b()?;

        Ok(NvPublicInfo {
            nv_index: nv_index_ret,
            name_alg,
            attributes,
            auth_policy,
            data_size,
            name,
        })
    }

    /// Read a block of data from NV RAM at the specified index and offset
    fn nv_read_raw_block(&mut self, nv_index: u32, size: u16, offset: u16) -> Result<Vec<u8>> {
        let command = CommandBuffer::new()
            .write_u32(nv_index) // authHandle (use the nv_index itself for public read)
            .write_u32(nv_index) // nvIndex
            // Authorization area (empty password session)
            .write_auth_empty_pw()
            .write_u16(size) // size
            .write_u16(offset) // offset
            .finalize(TpmSt::Sessions, TpmCc::NvRead);
        let mut resp = self.transmit(&command)?;

        // Parse response
        // Skip parameterSize (sessions response)
        let _parameter_size = resp.read_u32()?;

        // Read data (TPM2B_MAX_NV_BUFFER)
        let data = resp.read_tpm2b()?;

        Ok(data)
    }

    /// Read complete contents from an NV index (handles chunking automatically)
    fn nv_read(&mut self, nv_index: u32) -> Result<Vec<u8>> {
        // First, get the actual size of the NV index
        let nv_info = self.nv_readpublic(nv_index)?;

        // Read in chunks of 512 bytes (safe for most TPMs)
        const MAX_CHUNK: u16 = 512;
        let mut result = Vec::new();
        let mut offset = 0u16;
        let total_size = nv_info.data_size;

        while offset < total_size {
            let bytes_remaining = total_size - offset;
            let chunk_size = if bytes_remaining > MAX_CHUNK {
                MAX_CHUNK
            } else {
                bytes_remaining
            };

            let mut chunk = self.nv_read_raw_block(nv_index, chunk_size, offset)?;

            if chunk.is_empty() {
                bail!("Unexpected empty chunk at offset {}", offset);
            }

            offset += chunk.len() as u16;
            result.append(&mut chunk);
        }

        Ok(result)
    }

    /// Define (allocate) a new NV index
    ///
    /// Creates a new NV index with the specified size and attributes.
    /// The auth_value is used to protect read/write operations.
    fn nv_define_space(
        &mut self,
        nv_index: u32,
        data_size: u16,
        attributes: u32,
        name_alg: u16
    ) -> Result<()> {
        // Build TPM2B_NV_PUBLIC structure
        let mut nv_public = Vec::new();

        // TPMS_NV_PUBLIC
        nv_public.extend_from_slice(&nv_index.to_be_bytes());           // nvIndex
        nv_public.extend_from_slice(&name_alg.to_be_bytes());           // nameAlg
        nv_public.extend_from_slice(&attributes.to_be_bytes());         // attributes
        nv_public.extend_from_slice(&0u16.to_be_bytes());               // authPolicy size = 0 (empty)
        nv_public.extend_from_slice(&data_size.to_be_bytes());          // dataSize

        let command = CommandBuffer::new()
            .write_u32(TPM_RH_OWNER) // authHandle (owner hierarchy)
            .write_auth_empty_pw()            
            .write_tpm2b(&Vec::new()) // auth (TPM2B_AUTH) - the authorization value for the NV index
            .write_tpm2b(&nv_public) // publicInfo (TPM2B_NV_PUBLIC)
            .finalize(TpmSt::Sessions, TpmCc::NvDefineSpace);

        self.transmit(&command)?;
        Ok(())
    }

    /// Write data to an NV index
    ///
    /// Writes data to the NV index. For large data, this handles chunking automatically.
    /// The auth_value must match what was used in nv_define_space.
    fn nv_write(
        &mut self,
        nv_index: u32,
        data: &[u8]
    ) -> Result<()> {
        // Write in chunks (max 512 bytes per write for compatibility)
        const MAX_CHUNK: usize = 512;
        let mut offset = 0usize;

        while offset < data.len() {
            let chunk_size = std::cmp::min(MAX_CHUNK, data.len() - offset);
            let chunk = &data[offset..offset + chunk_size];

            let command = CommandBuffer::new()
                .write_u32(nv_index) // authHandle (the NV index itself)
                .write_u32(nv_index) // nvIndex
                .write_auth_empty_pw()
                .write_tpm2b(chunk) // data (TPM2B_MAX_NV_BUFFER)
                .write_u16(offset as u16)
                .finalize(TpmSt::Sessions, TpmCc::NvWrite);

            self.transmit(&command)?;
            offset += chunk_size;
        }

        Ok(())
    }

    /// Undefine (delete) an NV index
    ///
    /// Removes the NV index and frees its storage.
    fn nv_undefine_space(&mut self, nv_index: u32) -> Result<()> {
        let command = CommandBuffer::new()
            .write_u32(TPM_RH_OWNER) // authHandle (owner hierarchy)
            .write_u32(nv_index) // nvIndex
            .write_auth_empty_pw()
            .finalize(TpmSt::Sessions, TpmCc::NvUndefineSpace);

        self.transmit(&command)?;
        Ok(())
    }

    /// Find a free NV index in the specified range
    ///
    /// Searches for an available NV index that is not currently defined.
    /// Returns the first free index found, or an error if none are available.
    fn nv_find_free_index(&mut self, start: u32, end: u32) -> Result<u32> {
        let defined_indices = self.nv_indices()?;

        for candidate in start..=end {
            if !defined_indices.contains(&candidate) {
                return Ok(candidate);
            }
        }

        bail!("No free NV index found in range 0x{:08X}-0x{:08X}", start, end)
    }
}
