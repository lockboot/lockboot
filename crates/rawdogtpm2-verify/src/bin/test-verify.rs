// SPDX-License-Identifier: MIT OR Apache-2.0

//! Test binary for verifying TPM and Nitro attestations

use rawdogtpm2::attest;
use rawdogtpm2_verify::{
    verify_tpm_attestation, verify_nitro_attestation, AttestationOutput,
    parse_cert_chain_pem, extract_public_key, verify_ecdsa_p256, hash_public_key,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating attestation...");
    let nonce = b"test-nonce-12345";
    let attestation_json = attest(nonce)?;

    println!("Attestation generated successfully!");
    println!("JSON length: {} bytes", attestation_json.len());

    // Parse the output
    let output: AttestationOutput = serde_json::from_str(&attestation_json)?;

    // Check what we got
    println!("\nEK Certificates present:");
    println!("  RSA-2048: {}", output.ek_certificates.rsa_2048.is_some());
    println!("  ECC P-256: {}", output.ek_certificates.ecc_p256.is_some());
    println!("  ECC P-384: {}", output.ek_certificates.ecc_p384.is_some());

    println!("\nTPM attestations: {:?}", output.attestation.tpm.keys().collect::<Vec<_>>());
    println!("Nitro attestation: {}", output.attestation.nitro.is_some());

    // Verify TPM attestation
    for (key_type, attestation) in &output.attestation.tpm {
        println!("\nVerifying TPM attestation for {}...", key_type);

        let cert_pem = match key_type.as_str() {
            "rsa_2048" => output.ek_certificates.rsa_2048.as_ref(),
            "ecc_p256" => output.ek_certificates.ecc_p256.as_ref(),
            "ecc_p384" => output.ek_certificates.ecc_p384.as_ref(),
            _ => None,
        };

        let ek_pk = output.ek_public_keys.get(key_type);
        let ak_pk = output.signing_key_public_keys.get(key_type);

        // Debug info
        println!("  Attest data (nonce): {} bytes", attestation.attest_data.len() / 2);
        println!("  Signature length: {} bytes", attestation.signature.len() / 2);

        if let Some(ek) = ek_pk {
            println!("  EK pubkey X: {}...", &ek.x[..std::cmp::min(16, ek.x.len())]);
            println!("  EK pubkey Y: {}...", &ek.y[..std::cmp::min(16, ek.y.len())]);
        }

        if let Some(ak) = ak_pk {
            println!("  AK pubkey X: {}...", &ak.x[..std::cmp::min(16, ak.x.len())]);
            println!("  AK pubkey Y: {}...", &ak.y[..std::cmp::min(16, ak.y.len())]);
        }

        // Compare EK pubkey with certificate
        if let Some(cert) = cert_pem {
            if let Ok(chain) = parse_cert_chain_pem(cert) {
                if let Ok(cert_pubkey) = extract_public_key(&chain[0]) {
                    println!("  Cert pubkey length: {} bytes", cert_pubkey.len());
                    println!("  Cert pubkey: {}...", hex::encode(&cert_pubkey[..std::cmp::min(20, cert_pubkey.len())]));

                    // Check if EK from attestation matches certificate
                    if let Some(ek) = ek_pk {
                        let ek_x = hex::decode(&ek.x)?;
                        let ek_y = hex::decode(&ek.y)?;
                        let mut ek_pubkey = vec![0x04];
                        ek_pubkey.extend(&ek_x);
                        ek_pubkey.extend(&ek_y);

                        if ek_pubkey == cert_pubkey {
                            println!("  EK pubkey MATCHES certificate!");
                        } else {
                            println!("  EK pubkey DOES NOT MATCH certificate");
                            println!("    EK from output: {}", hex::encode(&ek_pubkey));
                            println!("    EK from cert:   {}", hex::encode(&cert_pubkey));
                        }
                    }
                }
            }
        }

        // Try verification
        if let (Some(cert), Some(ek), Some(ak)) = (cert_pem, ek_pk, ak_pk) {
            match verify_tpm_attestation(
                &attestation.attest_data,
                &attestation.signature,
                &ak.x,
                &ak.y,
                &ek.x,
                &ek.y,
                cert,
            ) {
                Ok(result) => {
                    println!("  Verification SUCCESS!");
                    println!("  Root pubkey hash: {}", result.root_pubkey_hash);

                    // Decode and show the nonce
                    let nonce_bytes = hex::decode(&result.nonce)?;
                    if let Ok(nonce_str) = std::str::from_utf8(&nonce_bytes) {
                        println!("  Nonce: {}", nonce_str);
                    } else {
                        println!("  Nonce: {} (binary)", result.nonce);
                    }
                }
                Err(e) => {
                    println!("  Verification FAILED: {}", e);

                    // Try manual verification with AK
                    println!("\n  Trying manual AK signature verification...");
                    let ak_x = hex::decode(&ak.x)?;
                    let ak_y = hex::decode(&ak.y)?;
                    let mut ak_pubkey = vec![0x04];
                    ak_pubkey.extend(&ak_x);
                    ak_pubkey.extend(&ak_y);

                    let nonce_data = hex::decode(&attestation.attest_data)?;
                    let signature = hex::decode(&attestation.signature)?;

                    match verify_ecdsa_p256(&nonce_data, &signature, &ak_pubkey) {
                        Ok(()) => {
                            println!("  AK signature verification SUCCESS!");
                            let ak_hash = hash_public_key(&ak_pubkey);
                            println!("  AK pubkey hash: {}", ak_hash);
                        }
                        Err(e2) => {
                            println!("  AK signature verification also failed: {}", e2);
                        }
                    }
                }
            }
        } else {
            println!("  Missing certificate, EK, or AK public key for {}", key_type);
        }
    }

    // Try Nitro if present
    if let Some(ref nitro) = output.attestation.nitro {
        println!("\nVerifying Nitro attestation...");
        match verify_nitro_attestation(&nitro.document, Some(nonce), None) {
            Ok(result) => {
                println!("  Verification SUCCESS!");
                println!("  Root pubkey hash: {}", result.root_pubkey_hash);
                println!("  Module ID: {}", result.document.module_id);
            }
            Err(e) => {
                println!("  Verification FAILED: {}", e);
            }
        }
    }

    Ok(())
}
