// SPDX-License-Identifier: MIT OR Apache-2.0

//! PCR (Platform Configuration Register) operations
//!
//! Extension trait providing PCR-related functionality for TPM.

use crate::{Tpm, TpmAlg, TpmCc, TpmSt, CommandBuffer, TPM_CAP_PCRS};
use anyhow::{Result, bail};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512, Digest};

/// Extension trait for PCR operations
pub trait PcrOps {
    /// Get list of active PCR banks (algorithms)
    fn get_active_pcr_banks(&mut self) -> Result<Vec<TpmAlg>>;

    /// Get PCR allocation info: which PCRs exist in which banks
    /// Returns Vec of (algorithm, Vec<pcr_indices>)
    fn get_pcr_allocation(&mut self) -> Result<Vec<(TpmAlg, Vec<u8>)>>;

    /// Read PCR values from a specific bank/algorithm
    /// Returns (pcr_index, value) tuples
    fn pcr_read_bank(&mut self, pcr_indices: &[u8], alg: TpmAlg) -> Result<Vec<(u8, Vec<u8>)>>;

    /// Read PCR values from all active banks
    /// Returns (pcr_index, algorithm, value) tuples
    fn pcr_read_all_banks(&mut self, pcr_indices: &[u8]) -> Result<Vec<(u8, TpmAlg, Vec<u8>)>>;

    /// Get which banks (algorithms) a specific PCR is allocated in
    fn get_pcr_allocated_banks(&mut self, pcr_index: u8) -> Result<Vec<TpmAlg>>;

    /// Extend a PCR in a specific bank with a digest value
    fn pcr_extend_bank(&mut self, pcr_index: u8, alg: TpmAlg, digest: &[u8]) -> Result<()>;

    /// Extend a PCR with arbitrary data (hashes the data for all active banks)
    fn pcr_extend(&mut self, pcr_index: u8, data: &[u8]) -> Result<()>;

    /// Read all PCRs from all active banks and return only non-zero ones
    /// Returns (pcr_index, algorithm, value) tuples
    fn read_nonzero_pcrs_all_banks(&mut self) -> Result<Vec<(u8, TpmAlg, Vec<u8>)>>;

    /// Get list of all allocated PCRs and which banks they're in
    /// Returns (pcr_index, Vec<algorithm>) tuples
    fn get_allocated_pcrs(&mut self) -> Result<Vec<(u8, Vec<TpmAlg>)>>;

    /// Read all allocated PCRs from all banks
    /// Returns (pcr_index, algorithm, value) tuples
    fn read_all_allocated_pcrs(&mut self) -> Result<Vec<(u8, TpmAlg, Vec<u8>)>>;

    /// Calculate PCR policy digest for the given PCR values
    fn calculate_pcr_policy_digest(pcr_values: &[(u8, Vec<u8>)]) -> Result<Vec<u8>>;
}

impl PcrOps for Tpm {
    fn get_active_pcr_banks(&mut self) -> Result<Vec<TpmAlg>> {
        let pcr_allocation = self.get_pcr_allocation()?;
        Ok(pcr_allocation.into_iter().map(|(alg, _)| alg).collect())
    }

        /// Get PCR allocation info: which PCRs exist in which banks
    /// Returns Vec of (algorithm, Vec<pcr_indices>)
    fn get_pcr_allocation(&mut self) -> Result<Vec<(TpmAlg, Vec<u8>)>> {
        let (_more_data, mut resp) = self.get_capability(TPM_CAP_PCRS, 0, 16)?;
        // Note: 16 banks is way more than any TPM has, so we ignore moreData

        // Parse capability-specific data: TPML_PCR_SELECTION
        let count = resp.read_u32()?;
        let mut allocation = Vec::new();

        for _ in 0..count {
            let hash_alg = resp.read_u16()?;
            let select_size = resp.read_u8()? as usize;
            let pcr_select = resp.read_bytes(select_size)?;

            // Parse the PCR selection bitmap to get allocated PCR indices
            let mut pcr_indices = Vec::new();
            for byte_idx in 0..select_size {
                for bit_idx in 0..8 {
                    if pcr_select[byte_idx] & (1 << bit_idx) != 0 {
                        let pcr_num = (byte_idx * 8 + bit_idx) as u8;
                        pcr_indices.push(pcr_num);
                    }
                }
            }

            // Convert to TpmAlg and add to list if valid
            if let Some(alg) = TpmAlg::from_u16(hash_alg) {
                allocation.push((alg, pcr_indices));
            }
        }

        Ok(allocation)
    }

    /// Read PCR values from a specific hash algorithm bank
    fn pcr_read_bank(&mut self, pcr_indices: &[u8], alg: TpmAlg) -> Result<Vec<(u8, Vec<u8>)>> {
        // PCR select bitmap (3 bytes for PCRs 0-23)
        // Note: Most TPMs only support 3 bytes even though spec allows 4
        let mut pcr_select = [0u8; 3];
        for &pcr in pcr_indices {
            if pcr < 24 {
                pcr_select[pcr as usize / 8] |= 1 << (pcr % 8);
            }
        }

        let command = CommandBuffer::new()
            // TPML_PCR_SELECTION count
            .write_u32(1)
            // TPMS_PCR_SELECTION
            .write_u16(alg as u16) // hash algorithm
            .write_u8(3) // sizeofSelect (3 bytes for PCRs 0-23)
            // PCR select bitmap
            .write_bytes(&pcr_select)
            .finalize(TpmSt::NoSessions, TpmCc::PcrRead);
        let mut resp = self.transmit(&command)?;

        // Parse response
        // Skip pcrUpdateCounter
        resp.read_u32()?;

        // Read TPML_PCR_SELECTION to see which PCRs are actually in the response
        let sel_count = resp.read_u32()?;
        let mut selected_pcrs = Vec::new();

        for _ in 0..sel_count {
            resp.read_u16()?; // hash alg (should match our request)
            let select_size = resp.read_u8()? as usize;
            let pcr_select = resp.read_bytes(select_size)?;

            // Parse bitmap to get actual PCR indices in response
            for byte_idx in 0..select_size {
                for bit_idx in 0..8 {
                    if pcr_select[byte_idx] & (1 << bit_idx) != 0 {
                        let pcr_num = (byte_idx * 8 + bit_idx) as u8;
                        selected_pcrs.push(pcr_num);
                    }
                }
            }
        }

        // Read TPML_DIGEST - these correspond to selected_pcrs in order
        let digest_count = resp.read_u32()?;
        let mut results = Vec::new();

        for i in 0..digest_count {
            let digest = resp.read_tpm2b()?;
            if (i as usize) < selected_pcrs.len() {
                results.push((selected_pcrs[i as usize], digest));
            }
        }

        Ok(results)
    }

    /// Read PCR values from all active banks
    /// Returns (pcr_index, algorithm, value) tuples
    ///
    /// Note: Only returns PCRs that are actually allocated in each bank.
    /// A PCR might not exist in all banks.
    fn pcr_read_all_banks(&mut self, pcr_indices: &[u8]) -> Result<Vec<(u8, TpmAlg, Vec<u8>)>> {
        let banks = self.get_active_pcr_banks()?;
        let mut all_results = Vec::new();

        for bank in banks {
            // Try to read from this bank, but don't fail if PCR doesn't exist in this bank
            match self.pcr_read_bank(pcr_indices, bank) {
                Ok(results) => {
                    for (index, value) in results {
                        all_results.push((index, bank, value));
                    }
                }
                Err(_) => {
                    // PCR might not be allocated in this bank, continue
                    continue;
                }
            }
        }

        Ok(all_results)
    }

    /// Get which banks a specific PCR is allocated in by trying to read it
    fn get_pcr_allocated_banks(&mut self, pcr_index: u8) -> Result<Vec<TpmAlg>> {
        let all_banks = self.get_active_pcr_banks()?;
        let mut allocated = Vec::new();

        for bank in all_banks {
            if let Ok(results) = self.pcr_read_bank(&[pcr_index], bank) {
                if !results.is_empty() {
                    allocated.push(bank);
                }
            }
        }

        Ok(allocated)
    }

    /// Extend a PCR with data using a specific hash algorithm
    ///
    /// This is a low-level function that extends a single bank.
    /// For most use cases, use pcr_extend() instead which extends all active banks.
    fn pcr_extend_bank(&mut self, pcr_index: u8, alg: TpmAlg, digest: &[u8]) -> Result<()> {
        // Validate digest size
        if let Some(expected_size) = alg.digest_size() {
            if digest.len() != expected_size {
                bail!("Digest size mismatch: expected {} bytes for {}, got {}",
                      expected_size, alg.name(), digest.len());
            }
        }

        // For PCR_Extend, all PCRs need authorization (even 16-23)
        // This is different from PCR_Read which doesn't need auth
        let cmd = CommandBuffer::new()
            .write_u32(pcr_index as u32) // pcrHandle
            .write_auth_empty_pw()
            // TPML_DIGEST_VALUES with single entry
            .write_u32(1) // count = 1
            .write_u16(alg as u16) // hashAlg
            .write_bytes(digest); // raw digest bytes

        let command = cmd.finalize(TpmSt::Sessions, TpmCc::PcrExtend);
        self.transmit(&command)?;

        Ok(())
    }

    /// Extend a PCR with data
    ///
    /// This function will:
    /// 1. Query which banks this PCR is allocated in
    /// 2. Hash the data with each allocated algorithm
    /// 3. Extend the PCR with all digests
    ///
    /// The TPM computes: PCR_new = Hash(PCR_old || digest)
    fn pcr_extend(&mut self, pcr_index: u8, data: &[u8]) -> Result<()> {
        // Get banks that are allocated for this specific PCR
        let banks = self.get_pcr_allocated_banks(pcr_index)?;

        if banks.is_empty() {
            bail!("No PCR banks allocated for PCR {}", pcr_index);
        }

        // Build the command with authorization
        // PCR_Extend always needs authorization (even for PCRs 16-23)
        let mut cmd = CommandBuffer::new()
            .write_u32(pcr_index as u32) // pcrHandle
            // Authorization area (password session with empty password)
            .write_auth_empty_pw();

        // TPML_DIGEST_VALUES - count
        cmd = cmd.write_u32(banks.len() as u32);

        // Hash data with each active algorithm and add to digest list
        for bank in &banks {
            cmd = cmd.write_u16(*bank as u16); // hashAlg

            let digest = match bank {
                TpmAlg::Sha1 => {
                    let mut hasher = Sha1::new();
                    hasher.update(data);
                    hasher.finalize().to_vec()
                },
                TpmAlg::Sha256 => {
                    let mut hasher = Sha256::new();
                    hasher.update(data);
                    hasher.finalize().to_vec()
                },
                TpmAlg::Sha384 => {
                    let mut hasher = Sha384::new();
                    hasher.update(data);
                    hasher.finalize().to_vec()
                },
                TpmAlg::Sha512 => {
                    let mut hasher = Sha512::new();
                    hasher.update(data);
                    hasher.finalize().to_vec()
                },
                _ => {
                    bail!("Unsupported hash algorithm for PCR extend: {:?}", bank);
                }
            };

            // Write digest as raw bytes (TPMU_HA), not TPM2B
            cmd = cmd.write_bytes(&digest);
        }

        let command = cmd.finalize(TpmSt::Sessions, TpmCc::PcrExtend);
        self.transmit(&command)?;

        Ok(())
    }

    /// Read all PCRs from all active banks and return only non-zero ones
    /// Returns (pcr_index, algorithm, value) tuples
    ///
    /// Note: Reads PCRs individually to handle non-contiguous PCR allocation.
    /// Some TPMs have gaps in PCR allocation (e.g., PCRs 0-7,9-10,17-23 allocated but not 8,11-16).
    ///
    /// Queries PCRs 0-23 (standard range) and attempts 24-31 (vendor-specific).
    /// Most TPMs only support PCRs 0-23 even though TPM 2.0 spec allows up to 31.
    fn read_nonzero_pcrs_all_banks(&mut self) -> Result<Vec<(u8, TpmAlg, Vec<u8>)>> {
        let mut all_nonzero = Vec::new();

        // Read each PCR individually to handle non-contiguous allocation
        // Query 0-23 (standard), attempt 24-31 (most TPMs don't support these)
        for pcr_idx in 0..32 {
            match self.pcr_read_all_banks(&[pcr_idx]) {
                Ok(values) => {
                    for (index, alg, value) in values {
                        // Only include non-zero PCRs
                        if !value.iter().all(|&b| b == 0) {
                            all_nonzero.push((index, alg, value));
                        }
                    }
                }
                Err(_) => {
                    // PCR not allocated in any bank, skip
                    continue;
                }
            }
        }

        Ok(all_nonzero)
    }

    /// Get list of allocated PCR indices across all banks
    /// Returns Vec of (pcr_index, Vec<algorithms>) showing which PCRs exist and in which banks
    fn get_allocated_pcrs(&mut self) -> Result<Vec<(u8, Vec<TpmAlg>)>> {
        let mut pcr_info = Vec::new();

        for pcr_idx in 0..32 {
            let banks = self.get_pcr_allocated_banks(pcr_idx)?;
            if !banks.is_empty() {
                pcr_info.push((pcr_idx, banks));
            }
        }

        Ok(pcr_info)
    }

    /// Read ALL allocated PCRs from all banks (including zero values)
    /// Returns (pcr_index, algorithm, value) tuples
    ///
    /// Use this (not read_nonzero_pcrs_all_banks) when creating PCR policies
    /// to ensure zero PCRs are included in the policy. This prevents an attacker
    /// from extending a currently-zero PCR to bypass the policy.
    fn read_all_allocated_pcrs(&mut self) -> Result<Vec<(u8, TpmAlg, Vec<u8>)>> {
        // Get PCR allocation from TPM (single fast query)
        let allocation = self.get_pcr_allocation()?;
        let mut all_results = Vec::new();

        // Read allocated PCRs from each bank
        for (bank, pcr_indices) in allocation {
            if pcr_indices.is_empty() {
                continue;
            }

            // TPM allocation bitmap is unreliable for bulk reads
            // Some TPMs claim PCRs are allocated but won't return them in bulk
            // Read each PCR individually to be safe
            for pcr_idx in pcr_indices {
                match self.pcr_read_bank(&[pcr_idx], bank) {
                    Ok(results) => {
                        for (index, value) in results {
                            all_results.push((index, bank, value));
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        Ok(all_results)
    }

    /// Calculate PCR policy digest for the given PCRs and their values
    fn calculate_pcr_policy_digest(pcr_values: &[(u8, Vec<u8>)]) -> Result<Vec<u8>> {
        // Step 1: Calculate PCR digest (hash of selected PCR values)
        let mut pcr_hasher = Sha256::new();
        for (_index, value) in pcr_values {
            pcr_hasher.update(value);
        }
        let pcr_digest = pcr_hasher.finalize();

        // Step 2: Build PCR selection structure
        let mut pcr_select = [0u8; 3]; // 3 bytes for PCRs 0-23
        for (index, _value) in pcr_values {
            if *index < 24 {
                pcr_select[*index as usize / 8] |= 1 << (*index % 8);
            }
        }

        // Step 3: Calculate policy digest
        // policyDigest = SHA256(previousDigest || TPM_CC_PolicyPCR || pcrSelection || pcrDigest)
        let mut policy_hasher = Sha256::new();

        // previousDigest starts as all zeros (32 bytes for SHA256)
        policy_hasher.update(&[0u8; 32]);

        // TPM_CC_PolicyPCR = 0x0000017F
        policy_hasher.update(&(TpmCc::PolicyPCR as u32).to_be_bytes());

        // TPML_PCR_SELECTION structure
        // count (4 bytes)
        policy_hasher.update(&1u32.to_be_bytes());
        // TPMS_PCR_SELECTION: hash (2 bytes) + sizeOfSelect (1 byte) + pcrSelect (3 bytes)
        policy_hasher.update(&(TpmAlg::Sha256 as u16).to_be_bytes());
        policy_hasher.update(&[3u8]); // sizeOfSelect
        policy_hasher.update(&pcr_select);

        // PCR digest
        policy_hasher.update(&pcr_digest);

        let policy_digest = policy_hasher.finalize();

        Ok(policy_digest.to_vec())
    }
}
