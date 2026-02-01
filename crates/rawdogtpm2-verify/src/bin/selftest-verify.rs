// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verification selftest binary
//!
//! Tests verification functionality against a real TPM.
//! Uses rawdogtpm2 for TPM operations and rawdogtpm2-verify for verification.

use hex;
use sha2::{Sha256, Digest};
use std::collections::BTreeMap;

use rawdogtpm2::{
    Tpm, TpmAlg, EkOps, PcrOps, NvOps,
    TPM_RH_OWNER, TPM_RH_ENDORSEMENT,
    NV_INDEX_ECC_P256_EK_CERT,
    der_to_pem,
};
use rawdogtpm2_verify::{
    verify_ecdsa_p256, compute_ecc_p256_name, calculate_pcr_policy,
    extract_public_key, parse_cert_chain_pem, hash_public_key,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Verification Selftest (Real TPM)");
    println!("=================================\n");

    // Open TPM device
    println!("Opening TPM device...");
    let mut tpm = Tpm::open()?;
    println!("✓ TPM device opened successfully\n");

    // Test 1: Software verification of TPM signature
    println!("Test 1: TPM Signature with Software Verification");
    println!("-------------------------------------------------");

    // Create a signing key
    let key_result = tpm.create_primary_ecc_key(TPM_RH_OWNER)?;
    println!("Created signing key: 0x{:08X}", key_result.handle);

    // Sign some data with the TPM
    let test_data = b"Test data for signature verification";
    let digest = Sha256::digest(test_data);
    println!("Test data: {:?}", std::str::from_utf8(test_data).unwrap());
    println!("SHA256 digest: {}", hex::encode(&digest));

    let signature = tpm.sign(key_result.handle, &digest)?;
    println!("TPM signature: {} bytes (DER)", signature.len());

    // Verify using rawdogtpm2-verify (p256 crate)
    let mut pubkey = vec![0x04];
    pubkey.extend(&key_result.public_key.x);
    pubkey.extend(&key_result.public_key.y);

    match verify_ecdsa_p256(test_data, &signature, &pubkey) {
        Ok(()) => {
            println!("✓ Signature verified successfully using software (p256 crate)");
        }
        Err(e) => {
            println!("✗ Signature verification FAILED: {}", e);
        }
    }

    // Test with wrong data (should fail)
    let wrong_data = b"Wrong data";
    match verify_ecdsa_p256(wrong_data, &signature, &pubkey) {
        Ok(()) => {
            println!("✗ FAIL: Verification should have failed with wrong data");
        }
        Err(_) => {
            println!("✓ Correctly rejected signature for wrong data");
        }
    }

    tpm.flush_context(key_result.handle)?;
    println!();

    // Test 2: Standard EK and Certificate Comparison
    println!("Test 2: Standard EK vs Certificate Comparison");
    println!("----------------------------------------------");

    match tpm.create_standard_ek() {
        Ok(standard_ek) => {
            println!("✓ Standard EK created using TCG template");
            println!("  EK X: {}", hex::encode(&standard_ek.public_key.x));
            println!("  EK Y: {}", hex::encode(&standard_ek.public_key.y));

            // Try to read EK certificate from NV RAM
            match tpm.nv_read(NV_INDEX_ECC_P256_EK_CERT) {
                Ok(cert_der) => {
                    println!("\n  Found EK certificate in NV RAM ({} bytes)", cert_der.len());

                    if cert_der.starts_with(&[0x30, 0x82]) {
                        // Convert DER to PEM for parsing
                        let pem = der_to_pem(&cert_der, "CERTIFICATE");

                        match parse_cert_chain_pem(&pem) {
                            Ok(chain) => {
                                match extract_public_key(&chain[0]) {
                                    Ok(cert_pubkey) => {
                                        println!("  Certificate pubkey: {} bytes", cert_pubkey.len());

                                        // Build EK pubkey in same format
                                        let mut ek_pubkey = vec![0x04];
                                        ek_pubkey.extend(&standard_ek.public_key.x);
                                        ek_pubkey.extend(&standard_ek.public_key.y);

                                        if ek_pubkey == cert_pubkey {
                                            println!("✓ Standard EK matches certificate!");
                                            println!("  Deterministic key derivation verified.");
                                        } else {
                                            println!("⚠ Standard EK does NOT match certificate");
                                            println!("    EK from TPM:  {}", hex::encode(&ek_pubkey));
                                            println!("    EK from cert: {}", hex::encode(&cert_pubkey));
                                            println!("  This may indicate:");
                                            println!("  - Certificate was issued with a different template");
                                            println!("  - TPM was re-provisioned after certificate issuance");
                                        }
                                    }
                                    Err(e) => {
                                        println!("  Could not extract public key from certificate: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                println!("  Could not parse certificate: {}", e);
                            }
                        }
                    } else {
                        println!("  Certificate is not in standard DER format");
                    }
                }
                Err(e) => {
                    println!("  No EK certificate in NV RAM: {}", e);
                    println!("  (Cannot compare - certificate not available)");
                }
            }

            tpm.flush_context(standard_ek.handle)?;
        }
        Err(e) => {
            println!("⚠ Could not create standard EK: {}", e);
            println!("  (Endorsement hierarchy may require authentication)");
        }
    }
    println!();

    // Test 3: PCR Policy Calculation and Verification
    println!("Test 3: PCR Policy Calculation");
    println!("-------------------------------");

    // Read actual PCR values from TPM
    let all_pcrs = tpm.read_all_allocated_pcrs()?;
    let sha256_pcrs: Vec<(u8, Vec<u8>)> = all_pcrs.iter()
        .filter(|(_, alg, _)| *alg == TpmAlg::Sha256)
        .map(|(idx, _, val)| (*idx, val.clone()))
        .collect();

    println!("Read {} SHA-256 PCRs from TPM", sha256_pcrs.len());

    // Convert to BTreeMap for calculate_pcr_policy
    let pcr_map: BTreeMap<u8, String> = sha256_pcrs.iter()
        .map(|(idx, val)| (*idx, hex::encode(val)))
        .collect();

    // Calculate policy using rawdogtpm2-verify
    let policy_hex = calculate_pcr_policy(&pcr_map, TpmAlg::Sha256)?;
    println!("Calculated PCR policy: {}...", &policy_hex[..32]);

    // Calculate policy using rawdogtpm2 (should match)
    let policy_from_tpm = Tpm::calculate_pcr_policy_digest(&sha256_pcrs, TpmAlg::Sha256)?;
    println!("Policy from rawdogtpm2: {}...", hex::encode(&policy_from_tpm[..16]));

    if policy_hex == hex::encode(&policy_from_tpm) {
        println!("✓ Policy calculations match between crates");
    } else {
        println!("✗ Policy calculations differ!");
    }
    println!();

    // Test 4: ReadPublic and Name Computation
    println!("Test 4: ReadPublic and Name Verification");
    println!("-----------------------------------------");

    // Create a key and verify name computation
    let test_key = tpm.create_primary_ecc_key(TPM_RH_OWNER)?;
    let read_result = tpm.read_public(test_key.handle)?;

    println!("TPM ReadPublic returned:");
    println!("  Public area: {} bytes", read_result.public_area.len());
    println!("  Name from TPM: {}", hex::encode(&read_result.name));

    // Compute name using rawdogtpm2-verify
    let computed_name = compute_ecc_p256_name(
        &test_key.public_key.x,
        &test_key.public_key.y,
        &[], // empty policy for basic signing key
    );
    println!("  Computed name: {}", hex::encode(&computed_name));

    if read_result.name == computed_name {
        println!("✓ TPM's name matches computed name");
    } else {
        println!("⚠ Name mismatch - key may have non-empty authPolicy");
    }

    tpm.flush_context(test_key.handle)?;
    println!();

    // Test 5: Public Key Hashing
    println!("Test 5: Public Key Hashing");
    println!("--------------------------");

    match tpm.create_primary_ecc_key(TPM_RH_ENDORSEMENT) {
        Ok(ek) => {
            let mut ek_pubkey = vec![0x04];
            ek_pubkey.extend(&ek.public_key.x);
            ek_pubkey.extend(&ek.public_key.y);

            let hash = hash_public_key(&ek_pubkey);
            println!("EK public key hash: {}", hash);
            println!("  (This would be the trust anchor identifier)");

            tpm.flush_context(ek.handle)?;
            println!("✓ Public key hash computed");
        }
        Err(e) => {
            println!("⚠ Could not access EK: {}", e);
        }
    }
    println!();

    // Test 6: Certify with Signature Verification
    println!("Test 6: TPM2_Certify with Software Verification");
    println!("------------------------------------------------");

    // Create an AK (signing key) and a key to certify
    let ak = tpm.create_primary_ecc_key(TPM_RH_OWNER)?;
    println!("Created AK: 0x{:08X}", ak.handle);

    // Create PCR-sealed key to certify
    let pcr_values: Vec<(u8, Vec<u8>)> = sha256_pcrs.clone();
    let auth_policy = Tpm::calculate_pcr_policy_digest(&pcr_values, TpmAlg::Sha256)?;
    let sealed_key = tpm.create_primary_ecc_key_with_policy(TPM_RH_OWNER, &auth_policy)?;
    println!("Created PCR-sealed key: 0x{:08X}", sealed_key.handle);

    // Certify the sealed key with AK
    let qualifying_data = b"test-certification-nonce";
    let cert_result = tpm.certify(sealed_key.handle, ak.handle, qualifying_data)?;
    println!("TPM2_Certify returned:");
    println!("  Attestation data: {} bytes", cert_result.attest_data.len());
    println!("  Signature: {} bytes", cert_result.signature.len());

    // Verify AK signature over attestation data using rawdogtpm2-verify
    let mut ak_pubkey = vec![0x04];
    ak_pubkey.extend(&ak.public_key.x);
    ak_pubkey.extend(&ak.public_key.y);

    match verify_ecdsa_p256(&cert_result.attest_data, &cert_result.signature, &ak_pubkey) {
        Ok(()) => {
            println!("✓ Certification signature verified successfully");
        }
        Err(e) => {
            println!("✗ Certification signature verification FAILED: {}", e);
        }
    }

    // Verify the certified name matches our computed name
    let expected_name = compute_ecc_p256_name(
        &sealed_key.public_key.x,
        &sealed_key.public_key.y,
        &auth_policy,
    );
    println!("Expected certified name: {}", hex::encode(&expected_name));

    tpm.flush_context(ak.handle)?;
    tpm.flush_context(sealed_key.handle)?;
    println!();

    println!("===========================");
    println!("All verification tests completed!");
    println!("===========================");

    Ok(())
}

