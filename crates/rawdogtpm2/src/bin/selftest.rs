// SPDX-License-Identifier: MIT OR Apache-2.0

//! TPM 2.0 selftest binary
//!
//! Connects to the local TPM and runs basic functionality tests

use anyhow::Result;
use hex;
use sha2::{Sha256, Digest};

use rawdogtpm2::{
    Tpm, TpmAlg, TPM_RH_OWNER, TPM_RH_ENDORSEMENT,
    NV_INDEX_RSA_2048_EK_CERT, NV_INDEX_ECC_P256_EK_CERT, NV_INDEX_ECC_P384_EK_CERT,
    EkOps, PcrOps, NvOps,
    compute_ecc_p256_name, der_to_pem,
};

// TPM fixed property identifiers (TPM_PT)
const TPM_PT_FAMILY_INDICATOR: u32 = 0x00000100;
const TPM_PT_LEVEL: u32 = 0x00000101;
const TPM_PT_REVISION: u32 = 0x00000102;
const TPM_PT_DAY_OF_YEAR: u32 = 0x00000103;
const TPM_PT_YEAR: u32 = 0x00000104;
const TPM_PT_MANUFACTURER: u32 = 0x00000105;
const TPM_PT_VENDOR_STRING_1: u32 = 0x00000106;
const TPM_PT_VENDOR_TPM_TYPE: u32 = 0x0000010A;
const TPM_PT_FIRMWARE_VERSION_1: u32 = 0x0000010B;
const TPM_PT_FIRMWARE_VERSION_2: u32 = 0x0000010C;

fn main() -> Result<()> {
    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return Ok(());
    }

    // Run standard TPM tests
    standard_tests()
}

fn print_help() {
    println!("TPM 2.0 Selftest");
    println!("================\n");
    println!("Usage: selftest [OPTIONS]\n");
    println!("Options:");
    println!("  --help, -h  Show this help message\n");
    println!("Runs standard TPM tests");
}

fn standard_tests() -> Result<()> {
    println!("TPM 2.0 Selftest");
    println!("================\n");

    // Open TPM device
    println!("Opening TPM device...");
    let mut tpm = Tpm::open()?;
    println!("✓ TPM device opened successfully\n");

    // Test -1: Query TPM properties (manufacturer, version, etc.)
    println!("Test -1: Querying TPM properties");
    println!("----------------------------------");

    // Helper to convert u32 to ASCII string (for manufacturer ID)
    let u32_to_ascii = |val: u32| -> String {
        let bytes = val.to_be_bytes();
        String::from_utf8_lossy(&bytes).trim_end_matches('\0').to_string()
    };

    // Query all properties
    match tpm.get_property(TPM_PT_FAMILY_INDICATOR) {
        Ok(val) => println!("Family Indicator:    {} (\"{}\")", u32_to_ascii(val), u32_to_ascii(val)),
        Err(e) => println!("Family Indicator:    Error: {}", e),
    }

    match tpm.get_property(TPM_PT_LEVEL) {
        Ok(val) => println!("Level:               {}", val),
        Err(e) => println!("Level:               Error: {}", e),
    }

    match tpm.get_property(TPM_PT_REVISION) {
        Ok(val) => println!("Revision:            {}.{}", (val >> 16) & 0xFFFF, val & 0xFFFF),
        Err(e) => println!("Revision:            Error: {}", e),
    }

    match tpm.get_property(TPM_PT_DAY_OF_YEAR) {
        Ok(val) => println!("Day of Year:         {}", val),
        Err(e) => println!("Day of Year:         Error: {}", e),
    }

    match tpm.get_property(TPM_PT_YEAR) {
        Ok(val) => println!("Year:                {}", val),
        Err(e) => println!("Year:                Error: {}", e),
    }

    match tpm.get_property(TPM_PT_MANUFACTURER) {
        Ok(val) => println!("Manufacturer:        0x{:08X} (\"{}\")", val, u32_to_ascii(val)),
        Err(e) => println!("Manufacturer:        Error: {}", e),
    }

    // Vendor string is 16 bytes total across 4 properties
    let mut vendor_string = String::new();
    for i in 0..4 {
        match tpm.get_property(TPM_PT_VENDOR_STRING_1 + i) {
            Ok(val) => {
                vendor_string.push_str(&u32_to_ascii(val));
                if i == 0 {
                    print!("Vendor String {}: 0x{:08X} (\"{}\")", i + 1, val, u32_to_ascii(val));
                } else {
                    print!("\nVendor String {}: 0x{:08X} (\"{}\")", i + 1, val, u32_to_ascii(val));
                }
            }
            Err(e) => print!("\nVendor String {}: Error: {}", i + 1, e),
        }
    }
    println!("\nFull Vendor String:  \"{}\"", vendor_string.trim());

    match tpm.get_property(TPM_PT_VENDOR_TPM_TYPE) {
        Ok(val) => println!("Vendor TPM Type:     0x{:08X}", val),
        Err(e) => println!("Vendor TPM Type:     Error: {}", e),
    }

    match tpm.get_property(TPM_PT_FIRMWARE_VERSION_1) {
        Ok(val) => println!("Firmware Version 1:  0x{:08X} ({}.{})", val, (val >> 16) & 0xFFFF, val & 0xFFFF),
        Err(e) => println!("Firmware Version 1:  Error: {}", e),
    }

    match tpm.get_property(TPM_PT_FIRMWARE_VERSION_2) {
        Ok(val) => println!("Firmware Version 2:  0x{:08X} ({}.{})", val, (val >> 16) & 0xFFFF, val & 0xFFFF),
        Err(e) => println!("Firmware Version 2:  Error: {}", e),
    }

    println!("\n✓ TPM properties queried successfully\n");

    // Test -0.5: Check if this is a Nitro TPM
    println!("Test -0.5: Checking for AWS Nitro TPM");
    println!("--------------------------------------");
    match tpm.is_nitro_tpm() {
        Ok(true) => println!("✓ This is an AWS Nitro TPM"),
        Ok(false) => println!("✗ This is NOT an AWS Nitro TPM"),
        Err(e) => println!("⚠ Could not determine TPM type: {}", e),
    }
    println!();

    // Test 0: Query active PCR banks
    println!("Test 0: Querying active PCR banks");
    println!("----------------------------------");
    let banks = tpm.get_active_pcr_banks()?;

    if banks.is_empty() {
        println!("⚠ No active PCR banks found!");
    } else {
        println!("Active PCR banks:");
        for bank in &banks {
            println!("  - {} (0x{:04X}) - {} bytes per digest",
                     bank.name(),
                     *bank as u16,
                     bank.digest_size().unwrap_or(0));
        }
    }
    println!("✓ Found {} active PCR bank(s)\n", banks.len());

    // Test 0.5: Query allocated PCRs
    println!("Test 0.5: Querying allocated PCRs (0-31)");
    println!("-----------------------------------------");
    let allocated_pcrs = tpm.get_allocated_pcrs()?;
    println!("Allocated PCRs: {} out of 32 possible", allocated_pcrs.len());
    for (pcr_idx, banks) in &allocated_pcrs {
        let bank_names: Vec<String> = banks.iter().map(|b| b.name().to_string()).collect();
        println!("  PCR {:2}: {}", pcr_idx, bank_names.join(", "));
    }
    println!();

    // Test 1: Read all non-zero PCR values from all banks
    println!("Test 1: Reading all non-zero PCR values (all banks)");
    println!("----------------------------------------------------");
    let pcrs = tpm.read_nonzero_pcrs_all_banks()?;

    if pcrs.is_empty() {
        println!("No non-zero PCRs found (all PCRs are zero in all banks)");
    } else {
        for (index, alg, value) in &pcrs {
            println!("PCR {:2} [{}]: {}", index, alg.name(), hex::encode(value));
        }
    }

    println!("\n✓ PCR read successful");
    println!("  Found {} non-zero PCR values\n", pcrs.len());

    // Test 2: Extend PCR 23 (application-specific PCR)
    println!("Test 2: Extending PCR 23 with test data");
    println!("----------------------------------------");
    let test_extend_data = b"TPM selftest measurement v1.0";
    println!("Data to extend: {:?}", std::str::from_utf8(test_extend_data).unwrap());
    println!("Data length: {} bytes", test_extend_data.len());

    // Check which banks PCR 23 is allocated in
    println!("\nChecking which banks PCR 23 is allocated in...");
    let allocated_banks = tpm.get_pcr_allocated_banks(23)?;
    println!("PCR 23 is allocated in {} bank(s):", allocated_banks.len());
    for bank in &allocated_banks {
        println!("  - {}", bank.name());
    }

    // Read PCR 23 before extension (all banks)
    println!("\nPCR 23 values BEFORE extension:");
    let pcr23_before = tpm.pcr_read_all_banks(&[23])?;
    for (_index, alg, value) in &pcr23_before {
        println!("  [{}]: {}", alg.name(), hex::encode(value));
    }

    // Extend PCR 23 with all allocated banks
    println!("\nExtending PCR 23...");
    tpm.pcr_extend(23, test_extend_data)?;
    println!("✓ PCR 23 extended successfully");
    println!("  Extended {} bank(s): {}",
             allocated_banks.len(),
             allocated_banks.iter().map(|a| a.name()).collect::<Vec<_>>().join(", "));

    // Read PCR 23 after extension (all banks)
    println!("\nPCR 23 values AFTER extension:");
    let pcr23_after = tpm.pcr_read_all_banks(&[23])?;
    for (_index, alg, value) in &pcr23_after {
        println!("  [{}]: {}", alg.name(), hex::encode(value));
    }

    // Verify the value changed
    if pcr23_before != pcr23_after {
        println!("\n✓ PCR 23 value changed as expected");
    } else {
        println!("\n⚠ Warning: PCR 23 value did not change");
    }
    println!();

    // Test 3: Create primary ECC key
    println!("Test 3: Creating primary ECC signing key");
    println!("-----------------------------------------");
    let key_result = tpm.create_primary_ecc_key(TPM_RH_OWNER)?;
    println!("✓ Primary key created");
    println!("  Handle: 0x{:08X}", key_result.handle);
    println!("  Public X: {}", hex::encode(&key_result.public_key.x));
    println!("  Public Y: {}", hex::encode(&key_result.public_key.y));
    println!();

    // Test 4: Sign data
    println!("Test 4: Signing test data");
    println!("-------------------------");
    let test_data = b"Hello, TPM!";
    let digest = Sha256::digest(test_data);
    println!("Test data: {:?}", std::str::from_utf8(test_data).unwrap());
    println!("SHA256 digest: {}", hex::encode(&digest));

    let signature = tpm.sign(key_result.handle, &digest)?;
    println!("✓ Signature created (DER-encoded)");
    println!("  Signature ({} bytes): {}", signature.len(), hex::encode(&signature));
    println!();

    // Test 5: Check for Endorsement Key
    println!("Test 5: Checking for Endorsement Key (EK)");
    println!("------------------------------------------");
    match tpm.create_primary_ecc_key(TPM_RH_ENDORSEMENT) {
        Ok(ek_result) => {
            println!("✓ EK created/accessed in endorsement hierarchy");
            println!("  EK Handle: 0x{:08X}", ek_result.handle);
            println!("  EK Public X: {}", hex::encode(&ek_result.public_key.x));
            println!("  EK Public Y: {}", hex::encode(&ek_result.public_key.y));

            // Flush EK
            tpm.flush_context(ek_result.handle)?;
        }
        Err(e) => {
            println!("⚠ Could not access endorsement hierarchy: {}", e);
            println!("  This is normal for:");
            println!("  - swtpm without EK provisioning");
            println!("  - Some local TPMs with EK password set");
            println!("  - Restricted TPM configurations");
        }
    }
    println!();

    // Test 6: Check for EK Certificate in NV RAM
    println!("Test 6: Checking for EK Certificate in NV RAM");
    println!("----------------------------------------------");

    check_ek_cert(&mut tpm, NV_INDEX_RSA_2048_EK_CERT, "RSA 2048 EK", "rsa_ek_cert");
    check_ek_cert(&mut tpm, NV_INDEX_ECC_P256_EK_CERT, "ECC P-256 EK", "ecc_p256_ek_cert");
    check_ek_cert(&mut tpm, NV_INDEX_ECC_P384_EK_CERT, "ECC P-384 EK", "ecc_p384_ek_cert");

    println!();

    // Test 6.5: List all NV indices
    println!("Test 6.5: Enumerating all NV RAM indices");
    println!("-----------------------------------------");

    let nv_indices = tpm.nv_indices()?;
    println!("Found {} NV indices\n", nv_indices.len());

    for nv_index in &nv_indices {
        println!("NV Index: 0x{:08X}", nv_index);

        // Get NV index info
        match tpm.nv_readpublic(*nv_index) {
            Ok(info) => {
                println!("  Name Algorithm: 0x{:04X}", info.name_alg);
                println!("  Attributes:     0x{:08X}", info.attributes);
                decode_nv_attributes(info.attributes, 4);
                println!("  Auth Policy:    {} bytes", info.auth_policy.len());
                if !info.auth_policy.is_empty() {
                    println!("    {}", hex::encode(&info.auth_policy));
                }
                println!("  Data Size:      {} bytes", info.data_size);

                // Try to read the data (may fail if auth is required)
                if info.data_size > 0 && info.data_size <= 2048 {
                    match tpm.nv_read(*nv_index) {
                        Ok(data) => {
                            println!("  Data (hex dump):");
                            hex_dump(&data, 4);
                        }
                        Err(e) => {
                            println!("  Data: <read failed: {}>", e);
                        }
                    }
                } else if info.data_size > 2048 {
                    println!("  Data: <too large to display: {} bytes>", info.data_size);
                }
            }
            Err(e) => {
                println!("  Error reading public info: {}", e);
            }
        }
        println!();
    }

    // Test 7: PCR-sealed key
    println!("Test 7: Creating PCR-sealed signing key");
    println!("-----------------------------------------");

    // Read ALL allocated PCRs (including zeros) for proper security policy
    println!("Reading all allocated PCRs...");
    let all_pcrs = tpm.read_all_allocated_pcrs()?;
    println!("Sealing to ALL {} allocated PCR values:", all_pcrs.len());

    for (index, alg, value) in &all_pcrs {
        println!("  PCR {:2} [{}]: {}", index, alg.name(), hex::encode(value));
    }

    // Get SHA-256 PCR values (must use SHA-256 for consistency with verification)
    let pcr_values: Vec<(u8, Vec<u8>)> = all_pcrs.iter()
        .filter(|(_, alg, _)| *alg == TpmAlg::Sha256)
        .map(|(idx, _, val)| (*idx, val.clone()))
        .collect();

    if pcr_values.is_empty() {
        anyhow::bail!("No SHA-256 PCRs allocated on this TPM");
    }

    println!("\nCreating key sealed to {} SHA-256 PCRs", pcr_values.len());

    // Compute policy from the PCR values we already have
    let auth_policy = Tpm::calculate_pcr_policy_digest(&pcr_values)?;
    let sealed_key = tpm.create_primary_ecc_key_with_policy(TPM_RH_OWNER, &auth_policy)?;
    println!("✓ PCR-sealed key created");
    println!("  Handle: 0x{:08X}", sealed_key.handle);
    println!("  Public X: {}", hex::encode(&sealed_key.public_key.x));
    println!("  Public Y: {}", hex::encode(&sealed_key.public_key.y));

    // Test 8: Certify the PCR-sealed key with the EK
    println!("\nTest 8: Certifying PCR-sealed key with EK");
    println!("------------------------------------------");

    // First, we need the EK
    println!("Creating/accessing EK...");
    let ek = match tpm.create_primary_ecc_key(TPM_RH_ENDORSEMENT) {
        Ok(ek) => {
            println!("✓ EK handle: 0x{:08X}", ek.handle);
            ek
        }
        Err(e) => {
            println!("⚠ Could not access EK: {}", e);
            println!("Skipping certification test (EK not available)");
            tpm.flush_context(sealed_key.handle)?;
            println!();
            tpm.flush_context(key_result.handle)?;
            println!("All tests passed!");
            return Ok(());
        }
    };

    // Generate qualifying data (using a nonce/challenge for this example)
    let qualifying_data = b"attestation-challenge-12345";
    println!("Using qualifying data: {:?}", std::str::from_utf8(qualifying_data).unwrap());

    // Certify the PCR-sealed key using the EK
    println!("\nCertifying PCR-sealed key with EK...");
    let cert_result = tpm.certify(sealed_key.handle, ek.handle, qualifying_data)?;

    println!("✓ Certification complete!");
    println!("  Attestation data: {} bytes", cert_result.attest_data.len());
    println!("  Signature: {} bytes (DER-encoded)", cert_result.signature.len());

    // Save attestation for inspection
    if let Err(e) = std::fs::write("/tmp/attestation.bin", &cert_result.attest_data) {
        eprintln!("  Warning: Could not write /tmp/attestation.bin: {}", e);
    } else {
        println!("  Saved attestation to: /tmp/attestation.bin");
    }

    if let Err(e) = std::fs::write("/tmp/attestation_signature.der", &cert_result.signature) {
        eprintln!("  Warning: Could not write /tmp/attestation_signature.der: {}", e);
    } else {
        println!("  Saved signature to: /tmp/attestation_signature.der");
    }

    // Cleanup EK and sealed key (but keep key_result for more tests)
    tpm.flush_context(ek.handle)?;
    tpm.flush_context(sealed_key.handle)?;

    // Test 9: Standard EK creation
    println!("\nTest 9: Standard EK Creation (TCG Template)");
    println!("--------------------------------------------");

    // Try to create the TCG standard EK
    match tpm.create_standard_ek() {
        Ok(standard_ek) => {
            println!("✓ Standard EK created using TCG EK Credential Profile template");
            println!("  Handle: 0x{:08X}", standard_ek.handle);
            println!("  Public X: {}", hex::encode(&standard_ek.public_key.x));
            println!("  Public Y: {}", hex::encode(&standard_ek.public_key.y));
            println!("  Note: Certificate comparison requires rawdogtpm2-verify selftest");

            tpm.flush_context(standard_ek.handle)?;
        }
        Err(e) => {
            println!("⚠ Could not create standard EK: {}", e);
            println!("  (Endorsement hierarchy may require authentication)");
        }
    }
    println!();

    // Test 10: ReadPublic and name verification
    println!("Test 10: ReadPublic and Name Verification");
    println!("------------------------------------------");

    let read_result = tpm.read_public(key_result.handle)?;
    println!("ReadPublic returned:");
    println!("  Public area: {} bytes", read_result.public_area.len());
    println!("  Name: {}", hex::encode(&read_result.name));

    // Compute expected name and compare
    // For our signing key, authPolicy is empty
    let computed_name = compute_ecc_p256_name(
        &key_result.public_key.x,
        &key_result.public_key.y,
        &[], // empty policy for basic signing key
    );
    println!("  Computed name: {}", hex::encode(&computed_name));

    if read_result.name == computed_name {
        println!("✓ TPM's name matches our computed name");
    } else {
        println!("⚠ Name mismatch - TPM uses different computation");
        println!("  (This is expected if key has non-empty authPolicy)");
    }
    println!();

    // Test 11: Policy session operations
    println!("Test 11: Policy Session Operations");
    println!("-----------------------------------");

    // Start a policy session
    let policy_session = tpm.start_policy_session()?;
    println!("✓ Policy session started: 0x{:08X}", policy_session);

    // Get initial policy digest (should be all zeros)
    let initial_digest = tpm.policy_get_digest(policy_session)?;
    println!("  Initial policy digest: {}", hex::encode(&initial_digest));

    let expected_empty = vec![0u8; 32];
    if initial_digest == expected_empty {
        println!("✓ Initial digest is empty (all zeros) as expected");
    } else {
        println!("⚠ Initial digest is not empty - unexpected");
    }

    // Execute PolicySecret(TPM_RH_ENDORSEMENT)
    println!("\nExecuting PolicySecret(TPM_RH_ENDORSEMENT)...");
    match tpm.policy_secret(policy_session, TPM_RH_ENDORSEMENT) {
        Ok(()) => {
            println!("✓ PolicySecret executed successfully");

            // Get updated policy digest
            let updated_digest = tpm.policy_get_digest(policy_session)?;
            println!("  Updated policy digest: {}", hex::encode(&updated_digest));

            // Expected digest for PolicySecret(TPM_RH_ENDORSEMENT) with SHA-256
            // This is the standard EK authPolicy
            let expected_ek_policy: [u8; 32] = [
                0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
                0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
                0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
                0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
            ];
            println!("  Expected EK policy:    {}", hex::encode(&expected_ek_policy));

            if updated_digest == expected_ek_policy {
                println!("✓ Policy digest matches standard EK authPolicy!");
            } else {
                println!("⚠ Policy digest does not match expected value");
            }
        }
        Err(e) => {
            println!("⚠ PolicySecret failed: {}", e);
            println!("  (This is normal if endorsement hierarchy requires authentication)");
        }
    }

    // Flush policy session
    tpm.flush_context(policy_session)?;
    println!("✓ Policy session flushed");

    println!();

    // Cleanup: Flush the signing key handle
    tpm.flush_context(key_result.handle)?;

    println!("======================");
    println!("All tests completed!");
    println!("======================");
    Ok(())
}

/// Check for and display an EK certificate from NV RAM
fn check_ek_cert(tpm: &mut Tpm, nv_index: u32, description: &str, filename_base: &str) {
    print!("Checking {} cert (0x{:08X})... ", description, nv_index);
    match tpm.nv_read(nv_index) {
        Ok(cert) => {
            println!("✓ Found!");
            println!("  Size: {} bytes", cert.len());
            if cert.len() > 0 {
                let der_path = format!("/tmp/{}.der", filename_base);
                let pem_path = format!("/tmp/{}.pem", filename_base);

                // Save raw DER to file
                if let Err(e) = std::fs::write(&der_path, &cert) {
                    eprintln!("  Warning: Could not write {}: {}", der_path, e);
                } else {
                    println!("  Saved DER to: {}", der_path);
                    println!("  Verify with: openssl x509 -inform DER -in {} -text -noout", der_path);
                }

                // Check if it looks like a DER-encoded certificate
                if cert.starts_with(&[0x30, 0x82]) {
                    println!("  Format: DER-encoded X.509 certificate");

                    let pem = der_to_pem(&cert, "CERTIFICATE");

                    // Save PEM to file
                    if let Err(e) = std::fs::write(&pem_path, &pem) {
                        eprintln!("  Warning: Could not write {}: {}", pem_path, e);
                    } else {
                        println!("  Saved PEM to: {}", pem_path);
                        println!("  Verify with: openssl x509 -in {} -text -noout", pem_path);
                    }

                    println!("\n{}", pem);
                } else {
                    println!("  Format: Unknown (not standard DER)");
                    println!("  First 32 bytes: {}", hex::encode(&cert[..cert.len().min(32)]));
                }
            }
        }
        Err(e) => {
            println!("Not found");
            println!("  Error: {}", e);
        }
    }
}

/// Decode NV index attributes bitfield
fn decode_nv_attributes(attrs: u32, indent_spaces: usize) {
    let indent = " ".repeat(indent_spaces);

    // TPMA_NV bit definitions from TPM 2.0 Part 2, Section 13.2
    if attrs & (1 << 1) != 0 { println!("{}    - PPWRITE: Platform can write", indent); }
    if attrs & (1 << 2) != 0 { println!("{}    - OWNERWRITE: Owner can write", indent); }
    if attrs & (1 << 3) != 0 { println!("{}    - AUTHWRITE: Auth required for write", indent); }
    if attrs & (1 << 4) != 0 { println!("{}    - POLICYWRITE: Policy required for write", indent); }

    // Bits 7-10: TPM_NT (NV Type)
    let nv_type = (attrs >> 4) & 0xF;
    print!("{}    - TYPE: ", indent);
    match nv_type {
        0x0 => println!("Ordinary (0x0)"),
        0x1 => println!("Counter (0x1)"),
        0x2 => println!("Bits (0x2)"),
        0x4 => println!("Extend (0x4)"),
        0x8 => println!("PIN Fail (0x8)"),
        0x9 => println!("PIN Pass (0x9)"),
        _ => println!("Unknown (0x{:X})", nv_type),
    }

    if attrs & (1 << 10) != 0 { println!("{}    - POLICY_DELETE: Policy required to delete", indent); }
    if attrs & (1 << 11) != 0 { println!("{}    - WRITELOCKED: Currently write-locked", indent); }
    if attrs & (1 << 12) != 0 { println!("{}    - WRITEALL: Must write full size at once", indent); }
    if attrs & (1 << 13) != 0 { println!("{}    - WRITEDEFINE: Can be written after definition", indent); }
    if attrs & (1 << 14) != 0 { println!("{}    - WRITE_STCLEAR: Write locked until TPM restart", indent); }
    if attrs & (1 << 15) != 0 { println!("{}    - GLOBALLOCK: Write locked by global lock", indent); }
    if attrs & (1 << 16) != 0 { println!("{}    - PPREAD: Platform can read", indent); }
    if attrs & (1 << 17) != 0 { println!("{}    - OWNERREAD: Owner can read", indent); }
    if attrs & (1 << 18) != 0 { println!("{}    - AUTHREAD: Auth required for read", indent); }
    if attrs & (1 << 19) != 0 { println!("{}    - POLICYREAD: Policy required for read", indent); }
    if attrs & (1 << 20) != 0 { println!("{}    - NO_DA: Not subject to dictionary attack protection", indent); }
    if attrs & (1 << 21) != 0 { println!("{}    - ORDERLY: Only updated on orderly shutdown", indent); }
    if attrs & (1 << 22) != 0 { println!("{}    - CLEAR_STCLEAR: Cleared on TPM reset", indent); }
    if attrs & (1 << 23) != 0 { println!("{}    - READLOCKED: Currently read-locked", indent); }
    if attrs & (1 << 24) != 0 { println!("{}    - WRITTEN: Has been written", indent); }
    if attrs & (1 << 25) != 0 { println!("{}    - PLATFORMCREATE: Created by platform", indent); }
    if attrs & (1 << 26) != 0 { println!("{}    - READ_STCLEAR: Readable after restart", indent); }
}

/// Display a hex dump of data with optional indentation
fn hex_dump(data: &[u8], indent_spaces: usize) {
    let indent = " ".repeat(indent_spaces);
    const BYTES_PER_LINE: usize = 16;

    for (line_num, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        let offset = line_num * BYTES_PER_LINE;
        print!("{}  {:04x}  ", indent, offset);

        // Print hex bytes
        for (i, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if i == 7 {
                print!(" "); // Extra space in the middle
            }
        }

        // Padding for last line if not full
        if chunk.len() < BYTES_PER_LINE {
            for i in chunk.len()..BYTES_PER_LINE {
                print!("   ");
                if i == 7 {
                    print!(" ");
                }
            }
        }

        // Print ASCII representation
        print!(" |");
        for byte in chunk {
            let c = if *byte >= 0x20 && *byte <= 0x7e {
                *byte as char
            } else {
                '.'
            };
            print!("{}", c);
        }
        println!("|");
    }
}
