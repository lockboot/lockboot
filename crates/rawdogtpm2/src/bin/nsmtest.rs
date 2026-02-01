// SPDX-License-Identifier: MIT OR Apache-2.0

//! AWS Nitro Security Module (NSM) test binary
//!
//! Tests NSM functionality via TPM vendor commands

use anyhow::Result;
use hex;
use rawdogtpm2::{Tpm, NsmOps};

fn main() -> Result<()> {
    println!("AWS Nitro TPM - NSM Test");
    println!("========================\n");

    // Open direct TPM device for NSM vendor commands
    println!("Opening TPM device (/dev/tpm0 - required for NSM vendor commands)...");
    let mut tpm = Tpm::open_direct()?;
    println!("✓ TPM device opened successfully\n");

    // Test 2: Attestation
    println!("Test 2: NSM Attestation");
    println!("-----------------------");

    println!("Requesting attestation document (no user_data, nonce, or public_key)...");
    match tpm.nsm_attest(None, None, None) {
        Ok(attestation_doc) => {
            println!("✓ Attestation successful!\n");

            println!("Attestation Document:");
            println!("  Size:         {} bytes", attestation_doc.len());
            println!("  First 64 bytes (hex): {}", hex::encode(&attestation_doc[..64.min(attestation_doc.len())]));

            println!("\n✓ All NSM tests passed!");
            Ok(())
        }
        Err(e) => {
            println!("✗ Attestation failed!");
            println!("  Error: {}", e);
            Err(e)
        }
    }
}
