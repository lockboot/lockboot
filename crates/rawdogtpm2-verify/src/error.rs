// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verification error types

use thiserror::Error;

/// Errors that can occur during verification
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("Invalid hex encoding: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Invalid attestation structure: {0}")]
    InvalidAttest(String),

    #[error("Signature verification failed: {0}")]
    SignatureInvalid(String),

    #[error("Certificate parsing failed: {0}")]
    CertificateParse(String),

    #[error("Certificate chain validation failed: {0}")]
    ChainValidation(String),

    #[error("CBOR parsing failed: {0}")]
    CborParse(String),

    #[error("COSE signature verification failed: {0}")]
    CoseVerify(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}
