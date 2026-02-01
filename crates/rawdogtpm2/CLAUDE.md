# rawdogtpm2

Minimal TPM 2.0 protocol implementation in pure Rust without C dependencies.

## Build

Debug build:
```bash
cargo build
```

For deployment, we target static musl binaries:
```bash
cargo build --target x86_64-unknown-linux-musl
```

## Architecture

- Direct communication with TPM via /dev/tpmrm0 (resource manager) or /dev/tpm0 (direct)
- No tpm2-tss or other C library dependencies
- Implements TPM 2.0 command/response protocol per TCG specification

## Key Modules

- `credential.rs` - Policy session operations and TPM object name computation
- `ek.rs` - EK and signing key operations
- `pcr.rs` - PCR read/extend operations
- `a9n.rs` - Attestation generation
- `nv.rs` - NV RAM read/write operations
- `nsm.rs` - AWS Nitro-specific vendor commands
