# stage1

A secure loader designed be exec'd after-setup by by `init` as **PID 1** as part of a Unified Kernel Image (UKI) initrd boot environment. The `stage1` executable fetches JSON config data from the cloud metadata service, then it downloads and verifies a stage2 binary, generates TPM attestations, then passed control to stage2. It establishes a chain of trust by:

1. **Fetching configuration** from cloud metadata services (AWS EC2, GCP, Azure)
2. **Downloading stage2 binary** from a specified URL
3. **Verifying SHA256 checksum** to ensure binary integrity
4. **Generating TPM attestation** before execution (captures PCR state)
5. **Extending TPM PCRs** 14 and 15 with measurements of the stage2 binary and configuration file
6. **Executing stage2** via `exec()`, replacing the PID 1 process

## Configuration Format

Stage1 expects a JSON configuration with a `_stage2` object containing architecture-specific configurations:

```json
{
  "_stage2": {
    "aarch64": {
      "url": "https://example.com/stage2-binary-arm64",
      "sha256": "abc123def456..."
    },
    "x86_64": {
      "url": "https://example.com/stage2-binary-amd64",
      "sha256": "def456abc123..."
    },
    "args": ["--flag", "value"]
  },
  "custom_field": "your-data-here"
}
```

### Architecture-Specific Fields

At least one architecture must be specified (`aarch64` or `x86_64`). Stage1 will automatically select the configuration matching its build architecture.

Each architecture configuration requires:
- **`url`** (string): HTTPS/HTTP URL to download the stage2 binary from
- **`sha256`** (string): Expected hex encoded SHA256 of the binary

### Optional Fields

- **`args`** (array of strings): Command-line arguments to pass to stage2 (applies to both architectures)

### Custom Fields

Any additional fields in the JSON are preserved, the raw file is written to `/tmp/stage2-config.json` for the stage2 binary to access.

## Usage Modes

### 1. Production Mode (PID 1 / No Arguments)

When running as PID 1 or without arguments, stage1 automatically fetches its JSON config from the cloud metadata service, uses the TPM to attest the instance state, then executes it.

### 2. Testing with Local File

```bash
stage1 --file config.json
```

Reads configuration from a local JSON file. Useful for testing before deploying to cloud.

### 3. Testing with Remote URL

```bash
stage1 --url https://example.com/config.json
```

Fetches configuration from a remote URL. The URL content is hashed and logged.

### 4. Generate Configuration

```bash
stage1 --make-config <aarch64|x86_64> <URL> [existing-config.json]
```

Downloads a binary, computes its SHA256 hash, and outputs a valid stage1 configuration with architecture-specific settings:

**Example:**
```bash
# Generate config for x86_64 binary
stage1 --make-config x86_64 https://example.com/stage2-x86_64

# Output:
{
  "_stage2": {
    "x86_64": {
      "url": "https://example.com/stage2-x86_64",
      "sha256": "a1b2c3d4e5f6..."
    }
  }
}
```

**Building a multi-architecture config:**
```bash
# First architecture creates the config
stage1 --make-config x86_64 https://example.com/stage2-amd64 > config.json

# Second architecture adds to existing config
stage1 --make-config aarch64 https://example.com/stage2-arm64 config.json > config.json
```

This allows you to use the same configuration file across different architectures - stage1 will automatically select the appropriate binary based on its build target.

### 5. Generate TPM Attestation

```bash
sudo stage1 --attest [challenge]
```

Requires root and access to `/dev/tpm0` to generate an attestation document containing:

- EK certificates and public key
- AK public key bound to all PCR values
- Signed quote with challenge
- Additional NitroTPM information

**Example:**
```bash
# Generate attestation with nonce
sudo stage1 --attest "challenge-from-verifier" > attestation.json

# Generate attestation without nonce
sudo stage1 --attest > attestation.json
```

The optional `challenge` can be used as a signing mechanism or as proof-of-liveness, by default it will use the current UTC UNIX integer timestamp.

## TPM Measurements

It first creates the following files in `/tmp/`:

| File | Content | Purpose |
|------|---------|---------|
| `/tmp/stage2.exe` | Downloaded binary | The stage2 executable (mode 0755) |
| `/tmp/stage2-config.json` | Full JSON config | Configuration data for stage2 |
| `/tmp/stage1.attest` | TPM attestation | Pre-execution attestation document |

Before executing stage2, the TPM PCRs are extended with cryptographic measurements:

| PCR | Purpose | Value Extended |
|-----|---------|----------------|
| **PCR 14** | Stage2 Binary | SHA256 hash of the downloaded binary |
| **PCR 15** | Configuration | SHA256 hash of the entire JSON config |

## Building

From the repository root:

```bash
cargo build --release -p stage1
```

The binary will be output to `target/x86_64-unknown-linux-musl/release/stage1`.

## Cloud Setup Examples

Stage1 automatically detects and retrieves configuration from:

| Cloud Provider | Metadata Service | Encoding | Header Required |
|----------------|------------------|----------|-----------------|
| **AWS EC2** | IMDSv2 (token-based) | Plain text | Token auth |
| **GCP** | metadata.google.internal | Plain text | `Metadata-Flavor: Google` |
| **Azure** | IMDS | Base64 | `Metadata: true` |

The boot loader tries each provider in sequence and uses the first successful response.


### AWS EC2

Set user-data when launching an instance:

```bash
aws ec2 run-instances \
  --image-id ami-xxxxx \
  --instance-type c6i.xlarge \
  --user-data file://config.json
```

Stage1 will automatically fetch from IMDSv2.

### GCP

Set custom metadata with the `user-data` key:

```bash
gcloud compute instances create INSTANCE_NAME \
  --metadata user-data="$(cat config.json)"
```

**Or via Terraform:**
```hcl
resource "google_compute_instance" "vm" {
  metadata = {
    user-data = file("config.json")
  }
}
```

### Azure

Set user-data on the VM:

```bash
az vm create \
  --name INSTANCE_NAME \
  --resource-group RESOURCE_GROUP \
  --user-data "$(cat config.json | base64 -w0)"
```

Note: Azure requires base64-encoding when setting, but stage1 automatically decodes it.

## Example Workflow

### 1. Build stage2 binaries for both architectures
```bash
# Build for x86_64
cargo build --release --target x86_64-unknown-linux-musl -p example-stage2

# Build for aarch64
cargo build --release --target aarch64-unknown-linux-musl -p example-stage2
```

### 2. Upload to S3 (or any hosting)
```bash
aws s3 cp target/x86_64-unknown-linux-musl/release/example-stage2 \
  s3://mybucket/stage2-amd64

aws s3 cp target/aarch64-unknown-linux-musl/release/example-stage2 \
  s3://mybucket/stage2-arm64
```

### 3. Generate multi-architecture configuration
```bash
# Add x86_64 config
stage1 --make-config x86_64 https://mybucket.s3.amazonaws.com/stage2-amd64 > config.json

# Add aarch64 config to the same file
stage1 --make-config aarch64 https://mybucket.s3.amazonaws.com/stage2-arm64 config.json > config.json
```

### 4. Test locally
```bash
sudo stage1 --file config.json
```

### 5. Deploy to cloud
```bash
# AWS: Set as user-data (works for both x86_64 and aarch64 instances)
aws ec2 run-instances --user-data file://config.json ...

# GCP: Set as metadata
gcloud compute instances create --metadata user-data="$(cat config.json)" ...

# Azure: Set as user-data (base64 encoded)
az vm create --user-data "$(cat config.json | base64 -w0)" ...
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
